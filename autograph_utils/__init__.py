# -*- coding: utf-8 -*-

"""Top-level package for Python Autograph Utilities."""

__author__ = """Ethan Glasser-Camp"""
__email__ = "eglassercamp@mozilla.com"
__version__ = "0.1.0"


import base64
import binascii
import re
from abc import ABC
from datetime import datetime

import cryptography
import ecdsa.util
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec as cryptography_ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256, SHA384
from cryptography.x509.oid import NameOID


class Cache(ABC):
    """An interface for caching x5u validity checks."""

    def get(self, url):
        pass

    def set(self, url, result):
        pass


class MemoryCache:
    """A simple Cache implementation that just uses a dictionary.

    This cache does not expire data and can therefore grow without
    bound. This may make it vulnerable to a denial-of-service attack.

    """

    def __init__(self):
        self.data = {}

    def get(self, url):
        return self.data.get(url)

    def set(self, url, result):
        self.data[url] = result


Cache.register(MemoryCache)


class SubjectNameCheck(ABC):
    """An interface for predicates that verify the subject name."""

    def check(self, subject_name):
        pass

    def describe(self):
        pass


class EndsWith:
    def __init__(self, domain):
        self.domain = domain

    def check(self, subject_name):
        return subject_name.endswith(self.domain)

    def describe(self):
        return f"ends with {self.domain!r}"


class ExactMatch:
    def __init__(self, domain):
        self.domain = domain

    def check(self, subject_name):
        return subject_name == self.domain

    def describe(self):
        return f"matches exactly {self.domain!r}"


BASE64_WRONG_LENGTH_RE = re.compile(
    r"Invalid base64-encoded string: number of data characters \(\d+\) cannot "
    r"be [123] more than a multiple of 4"
)


class BadCertificate(Exception):
    def __init__(self, extra):
        self.extra = extra

    @property
    def detail(self):
        return f"Bad certificate: {self.extra}"


class CertificateParseError(BadCertificate):
    def __init__(self, extra):
        self.extra = extra

    @property
    def detail(self):
        return f"Could not parse certificate: {self.extra}"


class CertificateNotYetValid(BadCertificate):
    def __init__(self, not_before):
        self.not_before = not_before

    @property
    def detail(self):
        return f"Certificate is not valid until {self.not_before}"


class CertificateExpired(BadCertificate):
    def __init__(self, not_after):
        self.not_after = not_after

    @property
    def detail(self):
        return f"Certificate expired on {self.not_after}"


class CertificateHasWrongRoot(BadCertificate):
    def __init__(self, *, expected, actual):
        self.expected = binascii.hexlify(expected).decode()
        self.actual = binascii.hexlify(actual).decode()

    @property
    def detail(self):
        return (
            "Certificate is not based on expected root hash. "
            f"Got '{self.actual}' expected '{self.expected}'"
        )


class CertificateHasWrongSubject(BadCertificate):
    def __init__(self, actual, check_description):
        self.check_description = check_description
        self.actual = actual

    @property
    def detail(self):
        return (
            f"Certificate does not have the expected subject. "
            f"Got {self.actual!r}, checking for {self.check_description}"
        )


class BadSignature(Exception):
    detail = "Unknown signature problem"


class SignatureDoesNotMatch(BadSignature):
    detail = "Signature does not correspond to this data"


class WrongSignatureSize(BadSignature):
    detail = "Signature is not the right number of bytes"


class SignatureVerifier:
    """A utility to verify the provenance of data.

    This class lets you verify that data is signed by a collection of
    certificates that chains back up to some well-known root
    hash. Certificate chains are identified by x5u. x5us are assumed
    to be static and so can be cached to save network traffic.

    :params ClientSession session: An aiohttp session, used to retrieve x5us.
    :params Cache cache: A cache used to store results for x5u verification.
    :params bytes root_hash: The expected hash for the first
        certificate in a chain.  This should not be encoded in any
        way. Hashes can be decoded using decode_mozilla_hash.
    :params SubjectNameCheck subject_name_check: Predicate to use to
        validate cert subject names. Defaults to
        EndsWith(".content-signature.mozilla.org").

    """

    def __init__(self, session, cache, root_hash, subject_name_check=None):
        self.session = session
        self.cache = cache
        self.root_hash = root_hash
        self.subject_name_check = subject_name_check or EndsWith(
            ".content-signature.mozilla.org"
        )

    algorithm = cryptography_ec.ECDSA(SHA384())

    async def verify(self, data, signature, x5u):
        """Verify that the data is signed by certs that chain up to the root hash.

        Returns True if the signature checks out and raises an
        exception otherwise.

        :param bytes data: Data that was signed.
        :param signature: Signature in Autograph format (described in
            Autograph docs as "DL/ECSSA representation of the R and S
            values (IEEE Std 1363-2000)"). This can be bytes or str.
        :param str x5u: URL of a certificate chain which was allegedly
            used to sign the data.
        :raises: BadCertificate if the certificate is bad;
            BadSignature if signature verification fails

        """
        cert = await self.verify_x5u(x5u)
        # Decode signature into the (r, s) components
        try:
            signature = base64.urlsafe_b64decode(signature)
        except binascii.Error as e:
            if BASE64_WRONG_LENGTH_RE.match(e.args[0]):
                raise WrongSignatureSize(
                    "Base64 encoded signature was not a multiple of 4"
                )
            raise

        try:
            r, s = ecdsa.util.sigdecode_string(
                signature, order=ecdsa.curves.NIST384p.order
            )
        except ecdsa.util.MalformedSignature:
            raise WrongSignatureSize()

        # Encode as DER for cryptography
        signature = encode_dss_signature(r, s)

        # Content signature implicitly adds a prefix to signed data
        data = b"Content-Signature:\x00" + data

        try:
            cert.public_key().verify(signature, data, self.algorithm)
        except cryptography.exceptions.InvalidSignature:
            raise SignatureDoesNotMatch()

        return True

    async def verify_x5u(self, url):
        cached = self.cache.get(url)
        if cached:
            return cached

        async with self.session.get(url) as response:
            response.raise_for_status()
            content = await response.read()
        pems = split_pem(content)
        certs = [
            x509.load_pem_x509_certificate(pem, backend=default_backend())
            for pem in pems
        ]

        now = _now()
        for cert in certs:
            if cert.not_valid_before > cert.not_valid_after:
                raise BadCertificate(
                    f"not_before ({cert.not_valid_before}) after "
                    f"not_after ({cert.not_valid_after})"
                )
            if now < cert.not_valid_before:
                raise CertificateNotYetValid(cert.not_valid_before)
            if now > cert.not_valid_after:
                raise CertificateExpired(cert.not_valid_after)

        # Verify chain of trust.
        chain = certs[::-1]
        root_hash = chain[0].fingerprint(SHA256())
        if root_hash != self.root_hash:
            raise CertificateHasWrongRoot(expected=self.root_hash, actual=root_hash)

        leaf_subject_name = (
            certs[0].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        )
        if not self.subject_name_check.check(leaf_subject_name):
            raise CertificateHasWrongSubject(
                leaf_subject_name, check_description=self.subject_name_check.describe()
            )

        res = certs[0]
        self.cache.set(url, res)
        return res


def split_pem(s):
    """Split a string containing many ASCII-armored PEM structures.

    No validation is performed on the PEM structures (even to the
    point of verifying that the BEGIN lines match the END lines).

    :param bytes s: bytes containing a list of PEM-encoded things
    :returns: List of bytes, each representing a single PEM-encoded thing
    """
    out = []
    acc = []
    state = "PRE"
    for line in s.split(b"\n"):
        if state == "PRE" and line.startswith(b"-----BEGIN "):
            acc.append(line)
            state = "BODY_OR_META"
        elif state == "PRE" and not line:
            pass
        elif state == "BODY_OR_META" and b":" in line:
            state = "META"
        elif state == "BODY" and line.startswith(b"-----END "):
            acc.append(line)
            out.append(b"\n".join(acc))
            acc = []
            state = "PRE"
        elif state == "META" and not line:
            state = "BODY"
        elif state == "BODY" or state == "BODY_OR_META":
            acc.append(line)
            state = "BODY"
        else:
            raise CertificateParseError(f'Unexpected input "{line}" in state "{state}"')

    if acc:
        raise CertificateParseError(f"Unexpected end of input. Leftover: {acc}")

    return out


def decode_mozilla_hash(s):
    """Convert a hash from pseudo-base16 colon-separated format.

    >>> decode_mozilla_hash('4C:35:B1:C3')
    b'\x4c\x35\xb1\xc3')
    """
    return bytes.fromhex(s.replace(":", " "))


def _now(self):
    """Mockable function to get "now".

    :returns: naive datetime representing a UTC timestamp
    """
    return datetime.utcnow()
