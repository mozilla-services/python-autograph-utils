#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for `autograph_utils` package."""

import datetime
import os.path
from unittest import mock

import aiohttp
import pytest
from aioresponses import aioresponses
from click.testing import CliRunner

import autograph_utils
from autograph_utils import MemoryCache, SignatureVerifier, decode_mozilla_hash, main

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


CERT_PATH = os.path.join(
    TESTS_BASE, "normandy.content-signature.mozilla.org-20210705.dev.chain"
)

FAKE_CERT_URL = (
    "https://example.com/normandy.content-signature.mozilla.org-20210705.dev.chain"
)

CERT_CHAIN = open(CERT_PATH).read()

DEV_ROOT_HASH = decode_mozilla_hash(
    "4C:35:B1:C3:E3:12:D9:55:E7:78:ED:D0:A7:E7:8A:38:"
    + "83:04:EF:01:BF:FA:03:29:B2:46:9F:3C:C5:EC:36:04"
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
        m.return_value = datetime.datetime(2019, 10, 23, 16, 16)
        # Yield the mock so someone can change the time if they want
        yield m


@pytest.fixture
async def aiohttp_session(loop):
    async with aiohttp.ClientSession() as s:
        yield s


def test_decode_mozilla_hash():
    assert decode_mozilla_hash("4C:35:B1:C3") == b"\x4c\x35\xb1\xc3"


async def test_verify_x5u(aiohttp_session, mock_with_x5u, cache, now_fixed):
    s = SignatureVerifier(aiohttp_session, cache, DEV_ROOT_HASH)
    await s.verify_x5u(FAKE_CERT_URL)


async def test_verify_signature(aiohttp_session, mock_with_x5u, cache, now_fixed):
    s = SignatureVerifier(aiohttp_session, cache, DEV_ROOT_HASH)
    await s.verify(SIGNED_DATA, SAMPLE_SIGNATURE, FAKE_CERT_URL)


async def test_verify_signature_bad_base64(
    aiohttp_session, mock_with_x5u, cache, now_fixed
):
    s = SignatureVerifier(aiohttp_session, cache, DEV_ROOT_HASH)
    with pytest.raises(autograph_utils.WrongSignatureSize):
        await s.verify(SIGNED_DATA, SAMPLE_SIGNATURE[:-3], FAKE_CERT_URL)


async def test_verify_signature_bad_numbers(
    aiohttp_session, mock_with_x5u, cache, now_fixed
):
    s = SignatureVerifier(aiohttp_session, cache, DEV_ROOT_HASH)
    with pytest.raises(autograph_utils.WrongSignatureSize):
        await s.verify(SIGNED_DATA, SAMPLE_SIGNATURE[:-4], FAKE_CERT_URL)


async def test_verify_x5u_expired(aiohttp_session, mock_with_x5u, cache, now_fixed):
    now_fixed.return_value = datetime.datetime(2022, 10, 23, 16, 16, 16)
    s = SignatureVerifier(aiohttp_session, cache, DEV_ROOT_HASH)
    with pytest.raises(autograph_utils.CertificateExpired) as excinfo:
        await s.verify(SIGNED_DATA, SAMPLE_SIGNATURE, FAKE_CERT_URL)

    assert (
        excinfo.value.detail == "Certificate expired in the past on 2021-07-05 21:57:15"
    )


async def test_verify_x5u_too_soon(aiohttp_session, mock_with_x5u, cache, now_fixed):
    now_fixed.return_value = datetime.datetime(2010, 10, 23, 16, 16, 16)
    s = SignatureVerifier(aiohttp_session, cache, DEV_ROOT_HASH)
    with pytest.raises(autograph_utils.CertificateNotYetValid) as excinfo:
        await s.verify(SIGNED_DATA, SAMPLE_SIGNATURE, FAKE_CERT_URL)

    assert excinfo.value.detail == "Certificate is not valid until 2016-07-06 21:57:15"


def test_command_line_interface():
    """Test the CLI."""
    runner = CliRunner()
    result = runner.invoke(main.main)
    assert result.exit_code == 0
    assert "autograph_utils.cli.main" in result.output
    help_result = runner.invoke(main.main, ["--help"])
    assert help_result.exit_code == 0
    assert "--help  Show this message and exit." in help_result.output
