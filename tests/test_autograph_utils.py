#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for `autograph_utils` package."""

import datetime
import os.path
from datetime import timezone
from unittest import mock

import aiohttp
import cryptography.x509
import pytest
import pytest_asyncio
from aioresponses import aioresponses
from click.testing import CliRunner
from cryptography.hazmat.backends import default_backend

import autograph_utils
from autograph_utils import (
    ExactMatch,
    MemoryCache,
    SignatureVerifier,
    decode_mozilla_hash,
    main,
)


TESTS_BASE = os.path.dirname(__file__)


SAMPLE_SIGNATURE = (
    "z7vcSigd9fKX-H8RrL2YBmji6bgmoaRfymtVLFyRcjbhCuXzTpexm2dQfKT-ru9K"
    + "D42sKXxZ9ZZmW2wnAy_yoj6nGXaDa35AyYSrQav602s3n4vJ4tYsJi3y0utsz6aD"
)


SIGNED_DATA = b"".join(
    [
        b'{"action":"console-log","arguments":{"message":"A recipe that was',
        b' used to generate a signature"},"capabilities":["action.console-l',
        b'og"],"filter_expression":"normandy.channel in [\\"default\\"]","i',
        b'd":10,"name":"python-autograph-utils-sample","revision_id":"16"}',
    ]
)


CERT_PATH = os.path.join(TESTS_BASE, "normandy.content-signature.mozilla.org-20210705.dev.chain")

FAKE_CERT_URL = "https://example.com/normandy.content-signature.mozilla.org-20210705.dev.chain"

CERT_CHAIN = open(CERT_PATH, "rb").read()

CERT_LIST = autograph_utils.split_pem(CERT_CHAIN)

DEV_ROOT_HASH = decode_mozilla_hash(
    "4C:35:B1:C3:E3:12:D9:55:E7:78:ED:D0:A7:E7:8A:38:"
    + "83:04:EF:01:BF:FA:03:29:B2:46:9F:3C:C5:EC:36:04"
)

STAGE_CERT_PATH = os.path.join(
    TESTS_BASE, "normandy.content-signature.mozilla.org-2019-12-04-18-15-23.chain"
)
STAGE_CERT_CHAIN = open(STAGE_CERT_PATH, "rb").read()
STAGE_CERT_LIST = autograph_utils.split_pem(STAGE_CERT_CHAIN)
STAGE_ROOT_HASH = decode_mozilla_hash(
    "DB:74:CE:58:E4:F9:D0:9E:E0:42:36:BE:6C:C5:C4:F6:"
    + "6A:E7:74:7D:C0:21:42:7A:03:BC:2F:57:0C:8B:9B:90"
)


@pytest.fixture
def mock_aioresponses():
    with aioresponses() as m:
        yield m


@pytest.fixture
def mock_with_x5u(mock_aioresponses):
    mock_aioresponses.get(FAKE_CERT_URL, status=200, body=CERT_CHAIN)
    return mock_aioresponses


@pytest.fixture
def cache():
    return MemoryCache()


@pytest.fixture
def now_fixed():
    with mock.patch("autograph_utils._now") as m:
        # A common static time used in a lot of tests.
        m.return_value = datetime.datetime(2019, 10, 23, 16, 16, tzinfo=timezone.utc)
        # Yield the mock so someone can change the time if they want
        yield m


@pytest_asyncio.fixture
async def aiohttp_session():
    async with aiohttp.ClientSession() as s:
        yield s


def mock_cert(real_cert):
    """Utility function to create a mock of a cert that has all the same
    data but can have fields overridden.

    """

    mock_cert = mock.MagicMock(wraps=real_cert)
    mock_cert.not_valid_before_utc = real_cert.not_valid_before_utc
    mock_cert.not_valid_after_utc = real_cert.not_valid_after_utc
    mock_cert.signature = real_cert.signature
    mock_cert.tbs_certificate_bytes = real_cert.tbs_certificate_bytes
    mock_cert.signature_hash_algorithm = real_cert.signature_hash_algorithm
    mock_cert.subject = real_cert.subject
    mock_cert.extensions = real_cert.extensions
    mock_cert.public_key = real_cert.public_key

    return mock_cert


def mock_cert_extension(cert, extension_cls, value):
    old_extensions = cert.extensions

    def get_extension_for_class_mock(query_cls):
        if query_cls == extension_cls:
            m = mock.Mock()
            m.value = value
            return m

        return old_extensions.get_extension_for_class(query_cls)

    cert.extensions = mock.Mock()
    cert.extensions.get_extension_for_class = get_extension_for_class_mock


def test_decode_mozilla_hash():
    assert decode_mozilla_hash("4C:35:B1:C3") == b"\x4c\x35\xb1\xc3"


async def test_verify_x5u(aiohttp_session, mock_with_x5u, cache, now_fixed):
    s = SignatureVerifier(aiohttp_session, cache, DEV_ROOT_HASH)
    await s.verify_x5u(FAKE_CERT_URL)


async def test_verify_x5u_caches_success(aiohttp_session, mock_with_x5u, cache, now_fixed):
    with mock.patch.object(cache, "set") as set_mock:
        s = SignatureVerifier(aiohttp_session, cache, DEV_ROOT_HASH)
        await s.verify_x5u(FAKE_CERT_URL)

        assert len(set_mock.call_args_list) == 1
        args, kwargs = set_mock.call_args_list[0]
        assert args[0] == FAKE_CERT_URL
        assert isinstance(args[1], cryptography.x509.Certificate)
        assert kwargs == {}


async def test_verify_x5u_returns_cache(aiohttp_session, mock_with_x5u, cache, now_fixed):
    with mock.patch.object(cache, "get") as get_mock:
        s = SignatureVerifier(aiohttp_session, cache, DEV_ROOT_HASH)
        res = await s.verify_x5u(FAKE_CERT_URL)
        assert res == get_mock.return_value


async def test_verify_signature(aiohttp_session, mock_with_x5u, cache, now_fixed):
    s = SignatureVerifier(aiohttp_session, cache, DEV_ROOT_HASH)
    await s.verify(SIGNED_DATA, SAMPLE_SIGNATURE, FAKE_CERT_URL)


async def test_verify_signature_bad_base64(aiohttp_session, mock_with_x5u, cache, now_fixed):
    s = SignatureVerifier(aiohttp_session, cache, DEV_ROOT_HASH)
    with pytest.raises(autograph_utils.WrongSignatureSize):
        await s.verify(SIGNED_DATA, SAMPLE_SIGNATURE[:-3], FAKE_CERT_URL)


async def test_verify_signature_bad_numbers(aiohttp_session, mock_with_x5u, cache, now_fixed):
    s = SignatureVerifier(aiohttp_session, cache, DEV_ROOT_HASH)
    with pytest.raises(autograph_utils.WrongSignatureSize):
        await s.verify(SIGNED_DATA, SAMPLE_SIGNATURE[:-4], FAKE_CERT_URL)


async def test_verify_x5u_expired(aiohttp_session, mock_with_x5u, cache, now_fixed):
    now_fixed.return_value = datetime.datetime(2022, 10, 23, 16, 16, 16, tzinfo=timezone.utc)
    s = SignatureVerifier(aiohttp_session, cache, DEV_ROOT_HASH)
    with pytest.raises(autograph_utils.CertificateExpired) as excinfo:
        await s.verify(SIGNED_DATA, SAMPLE_SIGNATURE, FAKE_CERT_URL)

    assert excinfo.value.detail == "Certificate expired on 2021-07-05 21:57:15+00:00"


async def test_verify_x5u_too_soon(aiohttp_session, mock_with_x5u, cache, now_fixed):
    now_fixed.return_value = datetime.datetime(2010, 10, 23, 16, 16, 16, tzinfo=timezone.utc)
    s = SignatureVerifier(aiohttp_session, cache, DEV_ROOT_HASH)
    with pytest.raises(autograph_utils.CertificateNotYetValid) as excinfo:
        await s.verify(SIGNED_DATA, SAMPLE_SIGNATURE, FAKE_CERT_URL)

    assert excinfo.value.detail == "Certificate is not valid until 2016-07-06 21:57:15+00:00"


async def test_verify_x5u_screwy_dates(aiohttp_session, mock_with_x5u, cache, now_fixed):
    now_fixed.return_value = datetime.datetime(2010, 10, 23, 16, 16, 16)
    s = SignatureVerifier(aiohttp_session, cache, DEV_ROOT_HASH)
    leaf_cert = cryptography.x509.load_pem_x509_certificate(
        CERT_LIST[0], backend=default_backend()
    )
    bad_cert = mock_cert(leaf_cert)
    bad_cert.not_valid_before_utc = leaf_cert.not_valid_after_utc
    bad_cert.not_valid_after_utc = leaf_cert.not_valid_before_utc
    with mock.patch("autograph_utils.x509.load_pem_x509_certificate") as x509:
        x509.return_value = bad_cert
        with pytest.raises(autograph_utils.BadCertificate) as excinfo:
            await s.verify(SIGNED_DATA, SAMPLE_SIGNATURE, FAKE_CERT_URL)

    assert excinfo.value.detail == (
        "Bad certificate: not_before (2021-07-05 21:57:15+00:00) "
        "after not_after (2016-07-06 21:57:15+00:00)"
    )


async def test_verify_x5u_name_exact_match(aiohttp_session, mock_with_x5u, cache, now_fixed):
    s = SignatureVerifier(
        aiohttp_session,
        cache,
        DEV_ROOT_HASH,
        subject_name_check=ExactMatch("normandy.content-signature.mozilla.org"),
    )
    await s.verify(SIGNED_DATA, SAMPLE_SIGNATURE, FAKE_CERT_URL)


async def test_verify_x5u_name_exact_doesnt_match(
    aiohttp_session, mock_with_x5u, cache, now_fixed
):
    s = SignatureVerifier(
        aiohttp_session,
        cache,
        DEV_ROOT_HASH,
        subject_name_check=ExactMatch("remote-settings.content-signature.mozilla.org"),
    )
    with pytest.raises(autograph_utils.CertificateHasWrongSubject) as excinfo:
        await s.verify(SIGNED_DATA, SAMPLE_SIGNATURE, FAKE_CERT_URL)

    assert excinfo.value.detail == (
        "Certificate does not have the expected subject. "
        "Got 'normandy.content-signature.mozilla.org', "
        "checking for matches exactly 'remote-settings.content-signature.mozilla.org'"
    )


async def test_verify_wrong_root_hash(aiohttp_session, mock_with_x5u, cache, now_fixed):
    wrong_root_hash = DEV_ROOT_HASH[:-1] + b"\x03"
    s = SignatureVerifier(
        aiohttp_session,
        cache,
        wrong_root_hash,
        subject_name_check=ExactMatch("remote-settings.content-signature.mozilla.org"),
    )
    with pytest.raises(autograph_utils.CertificateHasWrongRoot) as excinfo:
        await s.verify_x5u(FAKE_CERT_URL)

    actual = "4c35b1c3e312d955e778edd0a7e78a388304ef01bffa0329b2469f3cc5ec3604"
    expected = actual[:-1] + "3"

    assert excinfo.value.detail == (
        "Certificate is not based on expected root hash. " f"Got '{actual}' expected '{expected}'"
    )


async def test_root_hash_is_ignored_if_none(aiohttp_session, mock_with_x5u, cache, now_fixed):
    s = SignatureVerifier(
        aiohttp_session,
        cache,
        root_hash=None,
    )
    await s.verify_x5u(FAKE_CERT_URL)  # not raising


async def test_verify_broken_chain(aiohttp_session, mock_aioresponses, cache, now_fixed):
    # Drop next-to-last cert in cert list
    broken_chain = CERT_LIST[:1] + CERT_LIST[2:]
    mock_aioresponses.get(FAKE_CERT_URL, status=200, body=b"\n".join(broken_chain))
    s = SignatureVerifier(aiohttp_session, cache, DEV_ROOT_HASH)
    with pytest.raises(autograph_utils.CertificateChainBroken) as excinfo:
        await s.verify_x5u(FAKE_CERT_URL)

    assert excinfo.value.detail.startswith("Certificate chain is not continuous. ")
    assert excinfo.value.previous_cert == cryptography.x509.load_pem_x509_certificate(
        CERT_LIST[2], backend=default_backend()
    )
    assert excinfo.value.next_cert == cryptography.x509.load_pem_x509_certificate(
        CERT_LIST[0], backend=default_backend()
    )


async def test_verify_stage_cert_chain(aiohttp_session, mock_aioresponses, cache, now_fixed):
    mock_aioresponses.get(FAKE_CERT_URL, status=200, body=STAGE_CERT_CHAIN)
    s = SignatureVerifier(aiohttp_session, cache, STAGE_ROOT_HASH)
    await s.verify_x5u(FAKE_CERT_URL)


async def test_unknown_key(aiohttp_session, mock_with_x5u, cache, now_fixed):
    certs = [
        cryptography.x509.load_pem_x509_certificate(pem, backend=default_backend())
        for pem in CERT_LIST
    ]

    # Change public_key for an intermediate cert
    real_intermediate = certs[1]
    mock_intermediate = mock_cert(real_intermediate)
    mock_intermediate.public_key = mock.Mock()
    certs[1] = mock_intermediate

    with mock.patch("cryptography.x509.load_pem_x509_certificate") as load_cert_mock:
        load_cert_mock.side_effect = lambda *args, **kwargs: certs.pop(0)
        s = SignatureVerifier(aiohttp_session, cache, DEV_ROOT_HASH)
        with pytest.raises(autograph_utils.CertificateUnsupportedKeyType) as excinfo:
            await s.verify_x5u(FAKE_CERT_URL)

    assert excinfo.value.cert == mock_intermediate
    assert excinfo.value.key == mock_intermediate.public_key()


async def test_verify_name_constraints_raises(aiohttp_session, mock_with_x5u, cache, now_fixed):
    certs = [
        cryptography.x509.load_pem_x509_certificate(pem, backend=default_backend())
        for pem in STAGE_CERT_LIST
    ]
    # Intermediate cert has the name constraint.
    intermediate = certs[1]
    # Change name of leaf cert.
    mock_leaf = mock_cert(certs[0])
    fake_name = mock.Mock()
    fake_name.value = "bazinga.allizom.org"
    mock_leaf.subject = mock.Mock()
    mock_leaf.subject.get_attributes_for_oid.return_value = [fake_name]
    certs[0] = mock_leaf

    with mock.patch("cryptography.x509.load_pem_x509_certificate") as load_cert_mock:
        load_cert_mock.side_effect = lambda *args, **kwargs: certs.pop(0)
        s = SignatureVerifier(aiohttp_session, cache, STAGE_ROOT_HASH)
        with pytest.raises(autograph_utils.CertificateChainNameNotPermitted) as excinfo:
            await s.verify_x5u(FAKE_CERT_URL)

    assert " does not match the permitted names " in excinfo.value.detail
    assert excinfo.value.current == intermediate
    assert excinfo.value.next == mock_leaf


async def test_verify_name_constraints_excludes(aiohttp_session, mock_with_x5u, cache, now_fixed):
    certs = [
        cryptography.x509.load_pem_x509_certificate(pem, backend=default_backend())
        for pem in STAGE_CERT_LIST
    ]
    # Intermediate cert has the name constraint.
    real_intermediate = certs[1]
    real_constraints = real_intermediate.extensions.get_extension_for_class(
        cryptography.x509.NameConstraints
    ).value

    # Reverse meaning of constraints.
    reversed = mock.Mock()
    reversed.permitted_subtrees = real_constraints.excluded_subtrees
    reversed.excluded_subtrees = real_constraints.permitted_subtrees

    intermediate = mock_cert(real_intermediate)
    mock_cert_extension(intermediate, cryptography.x509.NameConstraints, reversed)
    certs[1] = intermediate

    leaf = certs[0]

    with mock.patch("cryptography.x509.load_pem_x509_certificate") as load_cert_mock:
        load_cert_mock.side_effect = lambda *args, **kwargs: certs.pop(0)
        s = SignatureVerifier(aiohttp_session, cache, STAGE_ROOT_HASH)
        with pytest.raises(autograph_utils.CertificateChainNameExcluded) as excinfo:
            await s.verify_x5u(FAKE_CERT_URL)

    assert " matches the excluded names " in excinfo.value.detail
    assert excinfo.value.current == intermediate
    assert excinfo.value.next == leaf


async def test_verify_basic_constraints_must_have_ca(
    aiohttp_session, mock_with_x5u, cache, now_fixed
):
    certs = [
        cryptography.x509.load_pem_x509_certificate(pem, backend=default_backend())
        for pem in STAGE_CERT_LIST
    ]
    real_intermediate = certs[1]
    intermediate = mock_cert(real_intermediate)
    basic_mock = mock.Mock()
    basic_mock.ca = False
    mock_cert_extension(intermediate, cryptography.x509.BasicConstraints, basic_mock)
    certs[1] = intermediate

    with mock.patch("cryptography.x509.load_pem_x509_certificate") as load_cert_mock:
        load_cert_mock.side_effect = lambda *args, **kwargs: certs.pop(0)
        s = SignatureVerifier(aiohttp_session, cache, STAGE_ROOT_HASH)
        with pytest.raises(autograph_utils.CertificateCannotSign) as excinfo:
            await s.verify_x5u(FAKE_CERT_URL)

    assert excinfo.value.detail.startswith("Certificate cannot be used for signing because ")
    assert excinfo.value.cert == intermediate
    assert excinfo.value.extra == "ca is false"


async def test_verify_basic_constraints_must_have_cert_signing(
    aiohttp_session, mock_with_x5u, cache, now_fixed
):
    certs = [
        cryptography.x509.load_pem_x509_certificate(pem, backend=default_backend())
        for pem in STAGE_CERT_LIST
    ]
    real_intermediate = certs[1]
    intermediate = mock_cert(real_intermediate)
    uses_mock = mock.Mock()
    uses_mock.key_cert_sign = False
    mock_cert_extension(intermediate, cryptography.x509.KeyUsage, uses_mock)
    certs[1] = intermediate

    with mock.patch("cryptography.x509.load_pem_x509_certificate") as load_cert_mock:
        load_cert_mock.side_effect = lambda *args, **kwargs: certs.pop(0)
        s = SignatureVerifier(aiohttp_session, cache, STAGE_ROOT_HASH)
        with pytest.raises(autograph_utils.CertificateCannotSign) as excinfo:
            await s.verify_x5u(FAKE_CERT_URL)

    assert excinfo.value.detail.startswith("Certificate cannot be used for signing because ")
    assert excinfo.value.cert == intermediate
    assert excinfo.value.extra == "key usage is incomplete"


async def test_verify_leaf_code_signing(aiohttp_session, mock_with_x5u, cache, now_fixed):
    certs = [
        cryptography.x509.load_pem_x509_certificate(pem, backend=default_backend())
        for pem in CERT_LIST
    ]

    # Change extended_key_usage for leaf cert
    real_leaf = certs[0]
    mock_leaf = mock_cert(real_leaf)
    fake_uses = [
        cryptography.x509.oid.ExtendedKeyUsageOID.CODE_SIGNING,
        cryptography.x509.oid.ExtendedKeyUsageOID.TIME_STAMPING,
    ]
    mock_cert_extension(mock_leaf, cryptography.x509.ExtendedKeyUsage, fake_uses)
    certs[0] = mock_leaf

    with mock.patch("cryptography.x509.load_pem_x509_certificate") as load_cert_mock:
        load_cert_mock.side_effect = lambda *args, **kwargs: certs.pop(0)
        s = SignatureVerifier(aiohttp_session, cache, DEV_ROOT_HASH)
        with pytest.raises(autograph_utils.CertificateLeafHasWrongKeyUsage) as excinfo:
            await s.verify_x5u(FAKE_CERT_URL)

    assert excinfo.value.detail.startswith(
        f"Leaf certificate {mock_leaf!r} should have extended key usage of just " "Code Signing. "
    )
    assert excinfo.value.cert == mock_leaf
    assert excinfo.value.key_usage == fake_uses


def test_command_line_interface():
    """Test the CLI."""
    runner = CliRunner()
    result = runner.invoke(main.main)
    assert result.exit_code == 0
    assert "autograph_utils.cli.main" in result.output
    help_result = runner.invoke(main.main, ["--help"])
    assert help_result.exit_code == 0
    assert "--help  Show this message and exit." in help_result.output
