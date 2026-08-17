"""Tests for the nostr announcement PoW of the swapserver plugin.

Covers the mining/collection path of ``electrum.util.gen_nostr_ann_pow`` /
``nostr_pow_worker`` and ``SwapManager.set_nostr_proof_of_work``.

The PoW scheme: leading zero bits of
    sha256(b"electrum-" + nostr_pubkey_xonly + nonce.to_bytes(32, "big"))

The tests deliberately do not run PoW searches: winning nonces are
precomputed constants, and the multiprocessing machinery (pool, manager)
is replaced by fakes. This keeps the suite fast and suitable for CI.
``TestNostrPowSearch`` at the bottom runs actual searches and is skipped
unless ELECTRUM_TESTS_NOSTR_POW is set (see there).
"""
import hashlib
import os
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from typing import Tuple
from unittest import mock

from electrum import util
from electrum import submarine_swaps
from electrum.util import get_nostr_ann_pow_amount, nostr_pow_worker, gen_nostr_ann_pow

from . import ElectrumTestCase


TEST_PUBKEY = bytes(range(32))  # any 32-byte x-only nostr pubkey

# precomputed winning nonces for TEST_PUBKEY:
NONCE_2_BITS = 3   # sha256 preimage digest starts with two zero bits
NONCE_4_BITS = 7
NONCE_8_BITS = 558
NONCE_8_BITS_DIGEST = bytes.fromhex(
    "00fe3e28a29bac792fe964e3947750a8d7d9c7613c8f6b3afef31cb3144842cd")


class _FakePool:
    """Stand-in for ProcessPoolExecutor; runs the workers in threads."""

    def __init__(self, max_workers=None):
        self._pool = ThreadPoolExecutor(max_workers=max_workers)

    def submit(self, fn, *args):
        return self._pool.submit(fn, *args)

    def shutdown(self, wait=False, cancel_futures=False):
        self._pool.shutdown(wait=wait, cancel_futures=cancel_futures)

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.shutdown(wait=False)


class _FakeManager:
    """Stand-in for multiprocessing.Manager; a threading.Event suffices
    as the shutdown event when the workers run in threads."""

    @staticmethod
    def Event():
        return threading.Event()


class TestNostrPowWorker(ElectrumTestCase):

    def test_winner_returns_digest_bytes(self):
        digest_or_hash, nonce = nostr_pow_worker(
            NONCE_2_BITS, TEST_PUBKEY, 1, hashlib.sha256, 256, threading.Event())
        self.assertIsInstance(digest_or_hash, bytes)
        expected = hashlib.sha256(
            b"electrum-" + TEST_PUBKEY + nonce.to_bytes(32, "big")).digest()
        self.assertEqual(expected, digest_or_hash)
        self.assertGreaterEqual(get_nostr_ann_pow_amount(TEST_PUBKEY, nonce), 1)


class TestGenNostrAnnPow(ElectrumTestCase):

    async def test_observer_result_completing_first_is_ignored(self):
        """The winning nonce must be collected even if a shutdown-observing
        worker's (None, None) result completes first.

        Real workers return (None, None) at their next 1M-hash block boundary
        after the winner sets the shutdown event; whether their result or the
        winner's own result reaches the event loop first is scheduling luck.
        """
        winner = (NONCE_8_BITS_DIGEST, NONCE_8_BITS)  # real workers return (digest, nonce)

        def fake_worker(nonce, nostr_pubk, tb, hash_function, hash_len_bits, shutdown):
            if nonce == 0:  # the worker that finds a nonce meeting the target
                time.sleep(0.05)  # "mining"
                shutdown.set()
                time.sleep(0.2)   # winner's result still in flight
                return winner
            while not shutdown.is_set():  # observers return at their next block boundary
                time.sleep(0.005)
            return None, None

        with mock.patch.object(util, "nostr_pow_worker", fake_worker), \
                mock.patch.object(util, "ProcessPoolExecutor", _FakePool), \
                mock.patch("multiprocessing.Manager", _FakeManager), \
                mock.patch("multiprocessing.cpu_count", return_value=4):
            nonce, pow_amount = await gen_nostr_ann_pow(TEST_PUBKEY, 8)
        self.assertEqual(NONCE_8_BITS, nonce)
        self.assertGreaterEqual(pow_amount, 8)

    async def test_no_winner_raises(self):
        def fake_worker(nonce, nostr_pubk, tb, hash_function, hash_len_bits, shutdown):
            return None, None

        with mock.patch.object(util, "nostr_pow_worker", fake_worker), \
                mock.patch.object(util, "ProcessPoolExecutor", _FakePool), \
                mock.patch("multiprocessing.Manager", _FakeManager), \
                mock.patch("multiprocessing.cpu_count", return_value=4):
            with self.assertRaisesRegex(Exception, "no worker returned a nonce"):
                await gen_nostr_ann_pow(TEST_PUBKEY, 8)


class TestSetNostrProofOfWork(ElectrumTestCase):

    def _make_sm(self, target: int, existing_nonce: int) -> SimpleNamespace:
        return SimpleNamespace(
            lnworker=SimpleNamespace(
                nostr_keypair=SimpleNamespace(pubkey=b"\x02" + TEST_PUBKEY)),
            config=SimpleNamespace(
                SWAPSERVER_POW_TARGET=target, SWAPSERVER_ANN_POW_NONCE=existing_nonce),
            logger=mock.MagicMock(),
        )

    async def test_none_nonce_is_not_stored(self):
        sm = self._make_sm(target=30, existing_nonce=0)

        async def broken_gen(pubk: bytes, target: int) -> Tuple[int, int]:
            return None, 0

        with mock.patch.object(submarine_swaps, "gen_nostr_ann_pow", broken_gen):
            with self.assertRaisesRegex(Exception, "does not reach the target"):
                await submarine_swaps.SwapManager.set_nostr_proof_of_work(sm)
        self.assertEqual(0, sm.config.SWAPSERVER_ANN_POW_NONCE)

    async def test_sub_target_nonce_is_not_stored(self):
        sm = self._make_sm(target=30, existing_nonce=0)

        async def weak_gen(pubk: bytes, target: int) -> Tuple[int, int]:
            return NONCE_4_BITS, get_nostr_ann_pow_amount(pubk, NONCE_4_BITS)

        with mock.patch.object(submarine_swaps, "gen_nostr_ann_pow", weak_gen):
            with self.assertRaisesRegex(Exception, "does not reach the target"):
                await submarine_swaps.SwapManager.set_nostr_proof_of_work(sm)
        self.assertEqual(0, sm.config.SWAPSERVER_ANN_POW_NONCE)

    async def test_nonce_meeting_target_is_stored(self):
        sm = self._make_sm(target=8, existing_nonce=0)

        async def good_gen(pubk: bytes, target: int) -> Tuple[int, int]:
            return NONCE_8_BITS, get_nostr_ann_pow_amount(pubk, NONCE_8_BITS)

        with mock.patch.object(submarine_swaps, "gen_nostr_ann_pow", good_gen):
            await submarine_swaps.SwapManager.set_nostr_proof_of_work(sm)
        self.assertEqual(NONCE_8_BITS, sm.config.SWAPSERVER_ANN_POW_NONCE)

    async def test_sufficient_existing_nonce_is_reused(self):
        sm = self._make_sm(target=8, existing_nonce=NONCE_8_BITS)

        async def must_not_mine(pubk: bytes, target: int) -> Tuple[int, int]:
            raise AssertionError("mining must be skipped when the stored nonce is sufficient")

        with mock.patch.object(submarine_swaps, "gen_nostr_ann_pow", must_not_mine):
            await submarine_swaps.SwapManager.set_nostr_proof_of_work(sm)


# TestNostrPowSearch performs actual PoW searches (repeated hashing), which we
# do not want to run on CI. Run locally with:
#   ELECTRUM_TESTS_NOSTR_POW=1 python -m pytest tests/test_nostr_pow.py -v
@unittest.skipUnless(
    os.environ.get("ELECTRUM_TESTS_NOSTR_POW"),
    "performs actual PoW searches; set ELECTRUM_TESTS_NOSTR_POW=1 to run locally")
class TestNostrPowSearch(ElectrumTestCase):

    async def test_pow_search_with_real_process_pool(self):
        target_bits = 16
        nonce, pow_amount = await gen_nostr_ann_pow(TEST_PUBKEY, target_bits)
        self.assertIsNotNone(nonce)
        self.assertGreaterEqual(pow_amount, target_bits)
        self.assertGreaterEqual(get_nostr_ann_pow_amount(TEST_PUBKEY, nonce), target_bits)

    async def test_repeated_pow_searches_all_return_valid_nonces(self):
        target_bits = 16
        for _ in range(5):
            nonce, pow_amount = await gen_nostr_ann_pow(TEST_PUBKEY, target_bits)
            self.assertIsNotNone(nonce)
            self.assertGreaterEqual(get_nostr_ann_pow_amount(TEST_PUBKEY, nonce), target_bits)
