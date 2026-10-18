"""Tests for the AuditLedger Python SDK — models and offline utilities."""

from __future__ import annotations

import json
import sys
import types
import pytest
from unittest.mock import MagicMock, patch


# ── Model tests ───────────────────────────────────────────────────────────────

class TestEvent:
    def _sample_dict(self) -> dict:
        return {
            "index": 0,
            "timestamp": 1_700_000_000,
            "event_type": "TRANSFER",
            "submitter": "GABC123",
            "metadata": "deadbeef",
            "event_hash": "ab" * 32,
            "prev_hash": "00" * 32,
        }

    def test_from_dict_round_trip(self):
        from audit_ledger.models import Event
        d = self._sample_dict()
        ev = Event.from_dict(d)
        assert ev.index == 0
        assert ev.timestamp == 1_700_000_000
        assert ev.event_type == "TRANSFER"
        assert ev.submitter == "GABC123"
        assert ev.metadata == bytes.fromhex("deadbeef")
        assert ev.event_hash == bytes.fromhex("ab" * 32)
        # "00" * 32 is a valid non-empty hex string → decoded to bytes(32)
        assert ev.prev_hash == bytes(32)

    def test_from_dict_defaults_missing_hashes(self):
        from audit_ledger.models import Event
        d = {"index": 1, "timestamp": 0, "event_type": "X", "submitter": "G", "metadata": ""}
        ev = Event.from_dict(d)
        # Missing hash fields → None
        assert ev.event_hash is None
        assert ev.prev_hash is None

    def test_from_dict_empty_metadata(self):
        from audit_ledger.models import Event
        d = self._sample_dict()
        d["metadata"] = ""
        ev = Event.from_dict(d)
        assert ev.metadata == b""


# ── Error tests ───────────────────────────────────────────────────────────────

class TestContractError:
    def test_known_error_code(self):
        from audit_ledger.models import ContractError
        err = ContractError(1)
        assert err.code == 1
        assert err.name == "CallerNotOwner"
        assert "CallerNotOwner" in str(err)

    def test_unknown_error_code(self):
        from audit_ledger.models import ContractError
        err = ContractError(99)
        assert "UnknownError(99)" in err.name

    def test_all_defined_codes(self):
        from audit_ledger.models import ContractError
        for code in range(1, 10):
            err = ContractError(code)
            assert err.code == code

    def test_is_audit_ledger_error(self):
        from audit_ledger.models import ContractError, AuditLedgerError
        assert isinstance(ContractError(1), AuditLedgerError)

    def test_rpc_error_is_audit_ledger_error(self):
        from audit_ledger.models import RPCError, AuditLedgerError
        err = RPCError("timeout")
        assert isinstance(err, AuditLedgerError)
        assert "timeout" in str(err)


# ── Client offline tests ──────────────────────────────────────────────────────

def _stub_stellar_sdk():
    """Inject a minimal stub for stellar_sdk so client.py can be imported."""
    stub = types.ModuleType("stellar_sdk")
    stub.SorobanServer = MagicMock
    stub.Keypair = MagicMock
    stub.soroban = types.ModuleType("stellar_sdk.soroban")
    stub.soroban.SorobanClient = MagicMock
    sys.modules.setdefault("stellar_sdk", stub)
    sys.modules.setdefault("stellar_sdk.soroban", stub.soroban)
    return stub


def _make_bare_client():
    """Return an AuditLedgerClient with no live server (server is a MagicMock)."""
    _stub_stellar_sdk()
    for mod in ["audit_ledger.client", "audit_ledger.cache",
                "audit_ledger.streaming", "audit_ledger.batch"]:
        sys.modules.pop(mod, None)
    from audit_ledger.client import AuditLedgerClient
    from audit_ledger.cache import LRUCache, CacheConfig
    client = AuditLedgerClient.__new__(AuditLedgerClient)
    client.contract_id = "CTEST"
    client.rpc_url = "https://soroban-testnet.stellar.org"
    client.network_passphrase = "Test SDF Network ; September 2015"
    client.server = MagicMock()
    client.source = None
    client._cache = LRUCache(CacheConfig(max_size=64, ttl_seconds=60.0))
    return client


class TestAuditLedgerClientOffline:
    """Tests that don't require a live Stellar RPC."""

    def _make_client(self):
        _stub_stellar_sdk()
        if "audit_ledger.client" in sys.modules:
            del sys.modules["audit_ledger.client"]
        from audit_ledger.client import AuditLedgerClient
        client = AuditLedgerClient.__new__(AuditLedgerClient)
        client.contract_id = "CTEST"
        client.rpc_url = "https://soroban-testnet.stellar.org"
        client.network_passphrase = "Test SDF Network ; September 2015"
        client.server = MagicMock()
        client.source = None
        return client

    def test_compute_event_id_is_deterministic(self):
        _stub_stellar_sdk()
        sys.modules.pop("audit_ledger.client", None)
        from audit_ledger.client import AuditLedgerClient
        id1 = AuditLedgerClient.compute_event_id("C1", "G1", "TX", b"data", 1000, 0)
        id2 = AuditLedgerClient.compute_event_id("C1", "G1", "TX", b"data", 1000, 0)
        assert id1 == id2
        assert len(id1) == 32

    def test_compute_event_id_differs_on_params(self):
        _stub_stellar_sdk()
        sys.modules.pop("audit_ledger.client", None)
        from audit_ledger.client import AuditLedgerClient
        id1 = AuditLedgerClient.compute_event_id("C1", "G1", "TX", b"data", 1000, 0)
        id2 = AuditLedgerClient.compute_event_id("C1", "G1", "TX", b"data2", 1000, 0)
        assert id1 != id2

    def test_verify_signature_invalid(self):
        _stub_stellar_sdk()
        sys.modules.pop("audit_ledger.client", None)
        from audit_ledger.client import AuditLedgerClient
        result = AuditLedgerClient.verify_signature(b"\x00" * 32, b"\x01" * 32, b"\x02" * 64)
        assert result is False

    def test_client_raises_without_stellar_sdk(self):
        saved = sys.modules.pop("stellar_sdk", None)
        saved_soroban = sys.modules.pop("stellar_sdk.soroban", None)
        sys.modules.pop("audit_ledger.client", None)
        try:
            from audit_ledger.client import AuditLedgerClient
            with pytest.raises(ImportError, match="stellar-sdk"):
                AuditLedgerClient(contract_id="X")
        finally:
            if saved:
                sys.modules["stellar_sdk"] = saved
            if saved_soroban:
                sys.modules["stellar_sdk.soroban"] = saved_soroban

    def test_parse_u32_from_dict(self):
        client = self._make_client()
        assert client._parse_u32({"u32": 42}) == 42
        assert client._parse_u32(7) == 7

    def test_invoke_raises_contract_error(self):
        from audit_ledger.models import ContractError
        client = self._make_client()
        client.server.invoke_contract = MagicMock(
            side_effect=Exception("Error(Contract, #2)")
        )
        with pytest.raises(ContractError) as exc:
            client._invoke("total_events")
        assert exc.value.code == 2

    def test_invoke_raises_rpc_error_on_unknown(self):
        from audit_ledger.models import RPCError
        client = self._make_client()
        client.server.invoke_contract = MagicMock(
            side_effect=Exception("network timeout")
        )
        with pytest.raises(RPCError):
            client._invoke("total_events")


# ── Streaming tests (#127 / #241) ─────────────────────────────────────────────

class TestStreamEvents:
    """Tests for AuditLedgerClient.stream_events() generator."""

    def _make_streaming_client(self, event_counts):
        """event_counts: list of totals returned on successive polls."""
        _stub_stellar_sdk()
        sys.modules.pop("audit_ledger.client", None)
        from audit_ledger.client import AuditLedgerClient
        from audit_ledger.models import Event
        from audit_ledger.cache import LRUCache, CacheConfig

        def _make_event(i):
            return Event(
                index=i, timestamp=1_700_000_000 + i,
                event_type="TX", submitter="GABC",
                metadata=b"", event_hash=None, prev_hash=None,
            )

        client = AuditLedgerClient.__new__(AuditLedgerClient)
        client.contract_id = "CTEST"
        client.server = MagicMock()
        client.source = None
        client.total_events = MagicMock(side_effect=event_counts)
        client.get_event_by_order = MagicMock(side_effect=_make_event)
        return client

    def test_yields_existing_events_in_order(self):
        client = self._make_streaming_client([3, 3])
        gen = client.stream_events(after_index=0, poll_interval_s=0)
        with patch("audit_ledger.streaming.time.sleep"):
            events = [next(gen) for _ in range(3)]
        assert [e.index for e in events] == [0, 1, 2]

    def test_resumes_from_after_index(self):
        client = self._make_streaming_client([5, 5])
        gen = client.stream_events(after_index=3, poll_interval_s=0)
        with patch("audit_ledger.streaming.time.sleep"):
            events = [next(gen) for _ in range(2)]
        assert [e.index for e in events] == [3, 4]

    def test_yields_new_events_as_they_appear(self):
        client = self._make_streaming_client([2, 4, 4])
        gen = client.stream_events(after_index=0, poll_interval_s=0)
        with patch("audit_ledger.streaming.time.sleep"):
            events = [next(gen) for _ in range(4)]
        assert [e.index for e in events] == [0, 1, 2, 3]

    def test_no_events_sleeps(self):
        client = self._make_streaming_client([0, 0, 1])
        gen = client.stream_events(after_index=0, poll_interval_s=1.5)
        with patch("audit_ledger.streaming.time.sleep") as mock_sleep:
            next(gen)
        assert mock_sleep.call_count >= 2
        mock_sleep.assert_called_with(1.5)


# ── Pagination tests (#128 / #241) ────────────────────────────────────────────

class TestGetEvents:
    """Tests for AuditLedgerClient.get_events() pagination."""

    def _make_client_with_events(self, n: int):
        _stub_stellar_sdk()
        if "audit_ledger.client" in sys.modules:
            del sys.modules["audit_ledger.client"]
        from audit_ledger.client import AuditLedgerClient
        from audit_ledger.models import Event

        def _make_event(i):
            return Event(
                index=i, timestamp=1_700_000_000 + i,
                event_type="TX", submitter="GABC",
                metadata=b"", event_hash=bytes(32), prev_hash=bytes(32),
            )

        client = AuditLedgerClient.__new__(AuditLedgerClient)
        client.contract_id = "CTEST"
        client.server = MagicMock()
        client.source = None
        client.total_events = MagicMock(return_value=n)

        def _invoke(method, params=None):
            if method == "get_event_by_order":
                order = params["order"]
                event = _make_event(order)
                return {
                    "index": event.index,
                    "timestamp": event.timestamp,
                    "event_type": event.event_type,
                    "submitter": event.submitter,
                    "metadata": event.metadata.hex(),
                    "event_hash": event.event_hash.hex(),
                    "prev_hash": event.prev_hash.hex(),
                }
            return None

        client._invoke = MagicMock(side_effect=_invoke)
        return client

    def test_default_limit(self):
        client = self._make_client_with_events(100)
        page = client.get_events()
        assert page.offset == 0
        assert page.limit == 50
        assert page.total == 100
        assert len(page.items) == 50
        assert page.items[0].index == 0
        assert page.items[49].index == 49

    def test_custom_offset_and_limit(self):
        client = self._make_client_with_events(100)
        page = client.get_events(offset=10, limit=20)
        assert page.offset == 10
        assert page.limit == 20
        assert len(page.items) == 20
        assert page.items[0].index == 10

    def test_boundary_offset_at_end(self):
        client = self._make_client_with_events(10)
        page = client.get_events(offset=10, limit=50)
        assert page.total == 10
        assert page.items == []

    def test_partial_last_page(self):
        client = self._make_client_with_events(7)
        page = client.get_events(offset=5, limit=50)
        assert len(page.items) == 2
        assert page.items[0].index == 5
        assert page.items[1].index == 6

    def test_page_dataclass_fields(self):
        from audit_ledger.models import Page
        p = Page(items=[], total=0, offset=0, limit=50)
        assert p.items == []
        assert p.total == 0


# ── Cursor-based paginated query tests (#862 / #867) ──────────────────────────

MAX_PAGE_LIMIT = 100


def _make_cursor_query_client(records):
    """Build a bare client whose _invoke serves cursor-paginated queries.

    ``records`` is a list of dicts with keys: id, timestamp, status, submitter.
    """
    _stub_stellar_sdk()
    sys.modules.pop("audit_ledger.client", None)
    from audit_ledger.client import AuditLedgerClient

    client = AuditLedgerClient.__new__(AuditLedgerClient)
    client.contract_id = "CTEST"
    client.server = MagicMock()
    client.source = None

    def _invoke(method, params=None):
        params = params or {}
        if method not in ("query_finops_records", "query_cross_contract_records"):
            return None
        cursor = params.get("cursor")
        limit = params.get("limit", 50)
        limit = min(limit, MAX_PAGE_LIMIT)
        ts_min = params.get("timestamp_min")
        ts_max = params.get("timestamp_max")
        status = params.get("status")
        submitter = params.get("submitter")

        # Deterministic ordering: (timestamp, id) ascending.
        ordered = sorted(records, key=lambda r: (r["timestamp"], r["id"]))
        filtered = []
        for r in ordered:
            if ts_min is not None and r["timestamp"] < ts_min:
                continue
            if ts_max is not None and r["timestamp"] > ts_max:
                continue
            if status is not None and r["status"] != status:
                continue
            if submitter is not None and r["submitter"] != submitter:
                continue
            filtered.append(r)

        start = 0
        if cursor is not None:
            for i, r in enumerate(filtered):
                if r["id"] == cursor:
                    start = i + 1
                    break
            else:
                start = len(filtered)

        window = filtered[start:start + limit]
        next_cursor = window[-1]["id"] if len(window) == limit and start + limit < len(filtered) else None
        return {"items": window, "next_cursor": next_cursor}

    client._invoke = MagicMock(side_effect=_invoke)
    return client


def _sample_records(n, statuses=("PENDING", "SETTLED"), submitters=("GAAA", "GBBB")):
    return [
        {
            "id": f"rec-{i:04d}",
            "timestamp": 1_700_000_000 + i,
            "status": statuses[i % len(statuses)],
            "submitter": submitters[i % len(submitters)],
        }
        for i in range(n)
    ]


class TestFinopsPaginatedQueries:
    """Cursor-based pagination + filtering for the finops query binding (#862)."""

    def _client(self, n=250):
        return _make_cursor_query_client(_sample_records(n))

    def _query(self, client, **kwargs):
        return client.query_finops_records(**kwargs)

    def test_empty_results(self):
        client = _make_cursor_query_client([])
        page = self._query(client)
        assert page["items"] == []
        assert page["next_cursor"] is None

    def test_single_item_page(self):
        client = self._client(1)
        page = self._query(client, limit=1)
        assert len(page["items"]) == 1
        assert page["items"][0]["id"] == "rec-0000"
        assert page["next_cursor"] is None

    def test_cursor_past_end_returns_empty(self):
        client = self._client(5)
        page = self._query(client, cursor="does-not-exist")
        assert page["items"] == []
        assert page["next_cursor"] is None

    def test_full_multi_page_traversal(self):
        client = self._client(250)
        seen = []
        cursor = None
        pages = 0
        while True:
            page = self._query(client, cursor=cursor, limit=50)
            seen.extend(r["id"] for r in page["items"])
            pages += 1
            cursor = page["next_cursor"]
            if cursor is None:
                break
        assert pages == 5
        assert len(seen) == 250
        assert len(set(seen)) == 250
        assert seen == sorted(seen)

    def test_page_limit_cap_enforced(self):
        client = self._client(250)
        page = self._query(client, limit=10_000)
        assert len(page["items"]) <= MAX_PAGE_LIMIT

    def test_filter_by_timestamp_range(self):
        client = self._client(50)
        lo = 1_700_000_010
        hi = 1_700_000_019
        page = self._query(client, timestamp_min=lo, timestamp_max=hi, limit=100)
        assert len(page["items"]) == 10
        assert all(lo <= r["timestamp"] <= hi for r in page["items"])

    def test_filter_by_status(self):
        client = self._client(50)
        page = self._query(client, status="SETTLED", limit=100)
        assert page["items"]
        assert all(r["status"] == "SETTLED" for r in page["items"])

    def test_filter_by_submitter(self):
        client = self._client(50)
        page = self._query(client, submitter="GBBB", limit=100)
        assert page["items"]
        assert all(r["submitter"] == "GBBB" for r in page["items"])

    def test_combined_filters(self):
        client = self._client(50)
        page = self._query(
            client,
            timestamp_min=1_700_000_000,
            timestamp_max=1_700_000_049,
            status="PENDING",
            submitter="GAAA",
            limit=100,
        )
        assert all(
            r["status"] == "PENDING" and r["submitter"] == "GAAA"
            for r in page["items"]
        )

    def test_deterministic_ordering(self):
        client = self._client(30)
        first = self._query(client, limit=100)["items"]
        second = self._query(client, limit=100)["items"]
        assert [r["id"] for r in first] == [r["id"] for r in second]
        assert [r["timestamp"] for r in first] == sorted(r["timestamp"] for r in first)


class TestCrossContractPaginatedQueries:
    """Cursor-based pagination + filtering for the cross-contract binding (#867)."""

    def _client(self, n=250):
        return _make_cursor_query_client(_sample_records(n))

    def _query(self, client, **kwargs):
        return client.query_cross_contract_records(**kwargs)

    def test_empty_results(self):
        client = _make_cursor_query_client([])
        page = self._query(client)
        assert page["items"] == []
        assert page["next_cursor"] is None

    def test_single_item_page(self):
        client = self._client(1)
        page = self._query(client, limit=1)
        assert len(page["items"]) == 1
        assert page["next_cursor"] is None

    def test_cursor_past_end_returns_empty(self):
        client = self._client(5)
        page = self._query(client, cursor="nope")
        assert page["items"] == []
        assert page["next_cursor"] is None

    def test_full_multi_page_traversal(self):
        client = self._client(250)
        seen = []
        cursor = None
        pages = 0
        while True:
            page = self._query(client, cursor=cursor, limit=50)
            seen.extend(r["id"] for r in page["items"])
            pages += 1
            cursor = page["next_cursor"]
            if cursor is None:
                break
        assert pages == 5
        assert len(seen) == 250
        assert len(set(seen)) == 250

    def test_page_limit_cap_enforced(self):
        client = self._client(250)
        page = self._query(client, limit=10_000)
        assert len(page["items"]) <= MAX_PAGE_LIMIT

    def test_filter_by_timestamp_range(self):
        client = self._client(50)
        page = self._query(
            client, timestamp_min=1_700_000_000, timestamp_max=1_700_000_004, limit=100
        )
        assert len(page["items"]) == 5

    def test_filter_by_status(self):
        client = self._client(50)
        page = self._query(client, status="PENDING", limit=100)
        assert page["items"]
        assert all(r["status"] == "PENDING" for r in page["items"])

    def test_filter_by_submitter(self):
        client = self._client(50)
        page = self._query(client, submitter="GAAA", limit=100)
        assert page["items"]
        assert all(r["submitter"] == "GAAA" for r in page["items"])

    def test_combined_filters(self):
        client = self._client(50)
        page = self._query(
            client,
            timestamp_min=1_700_000_000,
            timestamp_max=1_700_000_049,
            status="SETTLED",
            submitter="GBBB",
            limit=100,
        )
        assert all(
            r["status"] == "SETTLED" and r["submitter"] == "GBBB"
            for r in page["items"]
        )

    def test_deterministic_ordering(self):
        client = self._client(30)
        first = self._query(client, limit=100)["items"]
        second = self._query(client, limit=100)["items"]
        assert [r["id"] for r in first] == [r["id"] for r in second]
