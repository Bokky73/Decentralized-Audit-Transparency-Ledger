"""AuditLedger Python SDK — Pagination helpers.

Issue #248: Add cursor-based pagination, page iteration, total count caching,
and pagination state management.
Issue #852: Support the composite ordering-key cursor token format returned by
``src/cbdc_privacy.rs`` and expose ``next_cursor`` traversal on :class:`Page`.
"""

from __future__ import annotations

import base64
import binascii
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Callable,
    Generic,
    Iterator,
    List,
    Optional,
    TypeVar,
)

from .models import Page

T = TypeVar("T")

# ── Page size cap ─────────────────────────────────────────────────────────────

MAX_PAGE_LIMIT = 100
"""Hard cap on items per page, mirroring the on-chain ``PageLimit`` cap."""

#: Separator used by the on-chain composite cursor encoding.
_CURSOR_SEPARATOR = ":"


def clamp_limit(limit: int) -> int:
    """Clamp *limit* into the range ``[1, MAX_PAGE_LIMIT]``.

    Args:
        limit: Requested page size.

    Returns:
        The clamped page size.

    Raises:
        ValueError: If *limit* is not a positive integer.
    """
    if not isinstance(limit, int) or isinstance(limit, bool):
        raise ValueError(f"limit must be an integer, got {limit!r}")
    if limit < 1:
        raise ValueError(f"limit must be >= 1, got {limit}")
    return min(limit, MAX_PAGE_LIMIT)


clamp_page_limit = clamp_limit

# ── Cursor encoding ───────────────────────────────────────────────────────────


def encode_cursor(offset: int) -> str:
    """Encode an integer offset into an opaque cursor string.

    The cursor is a simple base-10 string.  Callers should treat it as an
    opaque token and not rely on its internal format.

    Args:
        offset: Zero-based item index.

    Returns:
        An opaque cursor string.
    """
    return str(offset)


def encode_composite_cursor(
    ledger_timestamp: int,
    status: int,
    submitter: str,
    sequence: int,
) -> str:
    """Encode a composite ordering key into an opaque cursor token.

    The on-chain ``src/cbdc_privacy.rs`` module orders records by
    ``(ledger_timestamp, status, submitter, sequence)`` so that ordering stays
    stable across ledger upgrades and archival restores.  This helper produces
    the matching opaque token.

    Args:
        ledger_timestamp: Ledger close time of the last returned record.
        status: Status enum discriminant of the last returned record.
        submitter: Submitter address of the last returned record.
        sequence: Monotonic sequence number of the last returned record.

    Returns:
        An opaque cursor string.
    """
    payload = {
        "t": int(ledger_timestamp),
        "s": int(status),
        "a": str(submitter),
        "n": int(sequence),
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_composite_cursor(cursor: str) -> "CompositeCursor":
    """Decode a composite cursor token produced by the on-chain module.

    Args:
        cursor: Opaque cursor token.

    Returns:
        The decoded :class:`CompositeCursor`.

    Raises:
        ValueError: If the cursor is malformed.
    """
    if not isinstance(cursor, str) or not cursor:
        raise ValueError(f"Invalid cursor: {cursor!r}")
    padded = cursor + "=" * (-len(cursor) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        payload = json.loads(raw.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"Invalid cursor: {cursor!r}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"Invalid cursor: {cursor!r}")
    try:
        return CompositeCursor(
            ledger_timestamp=int(payload["t"]),
            status=int(payload["s"]),
            submitter=str(payload["a"]),
            sequence=int(payload["n"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"Invalid cursor: {cursor!r}") from exc


def decode_cursor(cursor: str) -> int:
    """Decode a cursor string produced by :func:`encode_cursor`.

    Args:
        cursor: Cursor string previously returned by :func:`encode_cursor`.

    Returns:
        The decoded offset integer.

    Raises:
        ValueError: If the cursor is malformed.
    """
    try:
        value = int(cursor)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid cursor: {cursor!r}") from exc
    if value < 0:
        raise ValueError(f"Cursor offset must be non-negative, got {value}")
    return value


# ── Ordering-key cursors (finops / cross-contract) ────────────────────────────

#: Ordering keys used by the on-chain cursor encoding.  Both modules order
#: deterministically by ``(ledger_timestamp, sequence)`` so that pages remain
#: stable across ledger upgrades and archival restores.
ORDERING_KEYS = ("finops", "cross_contract")


def encode_ordering_cursor(
    ordering_key: str,
    ledger_timestamp: int,
    sequence: int,
) -> str:
    """Encode a deterministic ordering-key cursor.

    The cursor is ``"<ordering_key>:<ledger_timestamp>:<sequence>"``.  Callers
    must treat it as an opaque token.

    Args:
        ordering_key: One of :data:`ORDERING_KEYS`.
        ledger_timestamp: Ledger close time of the last returned item.
        sequence: Monotonic sequence number of the last returned item.

    Returns:
        An opaque cursor string.

    Raises:
        ValueError: If the ordering key or values are invalid.
    """
    if ordering_key not in ORDERING_KEYS:
        raise ValueError(
            f"Unknown ordering key {ordering_key!r}; expected one of {ORDERING_KEYS}"
        )
    if not isinstance(ledger_timestamp, int) or ledger_timestamp < 0:
        raise ValueError(
            f"ledger_timestamp must be a non-negative integer, got {ledger_timestamp!r}"
        )
    if not isinstance(sequence, int) or sequence < 0:
        raise ValueError(f"sequence must be a non-negative integer, got {sequence!r}")
    return f"{ordering_key}:{ledger_timestamp}:{sequence}"


def decode_ordering_cursor(cursor: str) -> "tuple[str, int, int]":
    """Decode a cursor produced by :func:`encode_ordering_cursor`.

    Args:
        cursor: Cursor string previously returned by
            :func:`encode_ordering_cursor`.

    Returns:
        A ``(ordering_key, ledger_timestamp, sequence)`` tuple.

    Raises:
        ValueError: If the cursor is malformed.
    """
    if not isinstance(cursor, str):
        raise ValueError(f"Invalid cursor: {cursor!r}")
    parts = cursor.split(":")
    if len(parts) != 3:
        raise ValueError(f"Invalid cursor: {cursor!r}")
    ordering_key, ts_raw, seq_raw = parts
    if ordering_key not in ORDERING_KEYS:
        raise ValueError(
            f"Unknown ordering key {ordering_key!r}; expected one of {ORDERING_KEYS}"
        )
    try:
        ledger_timestamp = int(ts_raw)
        sequence = int(seq_raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid cursor: {cursor!r}") from exc
    if ledger_timestamp < 0 or sequence < 0:
        raise ValueError(f"Invalid cursor: {cursor!r}")
    return ordering_key, ledger_timestamp, sequence


@dataclass(frozen=True)
class CompositeCursor:
    """A decoded composite ordering key.

    Attributes:
        ledger_timestamp: Ledger close time of the record.
        status: Status enum discriminant of the record.
        submitter: Submitter address of the record.
        sequence: Monotonic sequence number of the record.
    """

    ledger_timestamp: int
    status: int
    submitter: str
    sequence: int

    def encode(self) -> str:
        """Re-encode this ordering key as an opaque cursor token."""
        return encode_composite_cursor(
            self.ledger_timestamp, self.status, self.submitter, self.sequence
        )

    def sort_key(self) -> tuple:
        """Deterministic ordering key matching the on-chain sort order."""
        return (self.ledger_timestamp, self.status, self.submitter, self.sequence)


# ── Pagination state ──────────────────────────────────────────────────────────


@dataclass
class PaginationState:
    """Tracks the current position in a paginated sequence.

    Attributes:
        offset: Current zero-based item offset.
        limit: Number of items per page.
        total: Total item count (may be ``None`` before the first fetch).
        fetched: Total number of items fetched so far.
        page_number: Number of pages fetched so far (1-based after first fetch).
    """

    offset: int = 0
    limit: int = 50
    total: Optional[int] = None
    fetched: int = 0
    page_number: int = 0

    @property
    def has_next(self) -> bool:
        """True if there are more items to fetch."""
        if self.total is None:
            return True
        return self.offset < self.total

    @property
    def cursor(self) -> str:
        """Opaque cursor representing the current position."""
        return encode_cursor(self.offset)

    def advance(self, page_size: int) -> None:
        """Advance the state after fetching *page_size* items."""
        self.offset += page_size
        self.fetched += page_size
        self.page_number += 1

    def reset(self) -> None:
        """Reset the state back to the beginning."""
        self.offset = 0
        self.fetched = 0
        self.page_number = 0
        self.total = None
        self.next_cursor = None

    #: Opaque cursor token for the next page, as returned by the last fetch.
    next_cursor: Optional[str] = None

    def advance_cursor(self, next_cursor: Optional[str]) -> None:
        """Advance the state using a server-issued ``next_cursor`` token.

        Args:
            next_cursor: Token from the previous response, or ``None`` when the
                traversal is complete.
        """
        self.next_cursor = next_cursor
        self.page_number += 1
        if next_cursor is None:
            self.total = self.fetched


# ── Query filters ─────────────────────────────────────────────────────────────


@dataclass
class QueryFilters:
    """Multi-predicate filters for paginated read queries.

    All predicates are optional and combined with logical AND.  The same
    filter object must be supplied for every page of a traversal so that the
    ordering stays deterministic.

    Attributes:
        status: Optional status enum value (e.g. ``"pending"``).
        submitter: Optional submitter address.
        start_timestamp: Inclusive lower bound on ledger timestamp.
        end_timestamp: Inclusive upper bound on ledger timestamp.
    """

    status: Optional[str] = None
    submitter: Optional[str] = None
    start_timestamp: Optional[int] = None
    end_timestamp: Optional[int] = None

    def __post_init__(self) -> None:
        if self.start_timestamp is not None and self.start_timestamp < 0:
            raise ValueError("start_timestamp must be non-negative")
        if self.end_timestamp is not None and self.end_timestamp < 0:
            raise ValueError("end_timestamp must be non-negative")
        if (
            self.start_timestamp is not None
            and self.end_timestamp is not None
            and self.start_timestamp > self.end_timestamp
        ):
            raise ValueError("start_timestamp must be <= end_timestamp")

    def to_query_params(self) -> "dict[str, object]":
        """Render the filters as RPC query parameters.

        Returns:
            A dict containing only the predicates that were set.
        """
        params: "dict[str, object]" = {}
        if self.status is not None:
            params["status"] = self.status
        if self.submitter is not None:
            params["submitter"] = self.submitter
        if self.start_timestamp is not None:
            params["start_timestamp"] = self.start_timestamp
        if self.end_timestamp is not None:
            params["end_timestamp"] = self.end_timestamp
        return params


# ── Total count cache ─────────────────────────────────────────────────────────


@dataclass
class TotalCountCache:
    """A simple time-based cache for the total event count.

    Avoids redundant ``total_events()`` RPC calls within a short window.

    Args:
        ttl_seconds: How long a cached value remains valid.

    Example::

        cache = TotalCountCache(ttl_seconds=10)
        total = cache.get_or_fetch(client.total_events)
    """

    ttl_seconds: float = 10.0
    _value: Optional[int] = field(default=None, init=False, repr=False)
    _fetched_at: Optional[float] = field(default=None, init=False, repr=False)

    def get_or_fetch(self, fetch_fn: Callable[[], int]) -> int:
        """Return the cached total or call *fetch_fn* to refresh it.

        Args:
            fetch_fn: Zero-argument callable that returns the current total.

        Returns:
            The (possibly cached) event total.
        """
        now = time.monotonic()
        if (
            self._value is None
            or self._fetched_at is None
            or (now - self._fetched_at) > self.ttl_seconds
        ):
            self._value = fetch_fn()
            self._fetched_at = now
        return self._value

    def invalidate(self) -> None:
        """Invalidate the cached value, forcing a fresh fetch next time."""
        self._value = None
        self._fetched_at = None

    @property
    def cached_value(self) -> Optional[int]:
        """The currently cached total, or ``None`` if not yet fetched."""
        return self._value


# ── Page iterator ─────────────────────────────────────────────────────────────


class PageIterator(Generic[T]):
    """Iterate over pages returned by a paginated fetch function.

    The iterator lazily calls *fetch_fn* for each page and stops when the
    page's ``total`` has been exhausted.

    Args:
        fetch_fn: Callable with signature ``(offset, limit) -> Page[T]``.
        limit: Items per page.
        start_offset: Initial offset (default ``0``).

    Example::

        for page in PageIterator(client.get_events, limit=20):
            for event in page.items:
                process(event)
    """

    def __init__(
        self,
        fetch_fn: Callable[[int, int], Page[T]],
        limit: int = 50,
        start_offset: int = 0,
    ) -> None:
        self._fetch = fetch_fn
        self._state = PaginationState(offset=start_offset, limit=limit)

    def __iter__(self) -> Iterator[Page[T]]:
        return self

    def __next__(self) -> Page[T]:
        if not self._state.has_next:
            raise StopIteration

        page: Page[T] = self._fetch(self._state.offset, self._state.limit)

        # Update total from the response so has_next stays accurate
        self._state.total = page.total

        if not page.items:
            raise StopIteration

        next_cursor = getattr(page, "next_cursor", None)
        if next_cursor is not None:
            # Cursor-based traversal: the server tells us where to resume.
            self._state.offset += len(page.items)
            self._state.fetched += len(page.items)
            self._state.advance_cursor(next_cursor)
        else:
            self._state.advance(len(page.items))
        return page

    @property
    def state(self) -> PaginationState:
        """The current :class:`PaginationState`."""
        return self._state

    def reset(self) -> None:
        """Reset the iterator to the beginning."""
        self._state.reset()


# ── Filtered cursor page iterator ─────────────────────────────────────────────


class FilteredPageIterator(Generic[T]):
    """Iterate over filtered pages using opaque ``next_cursor`` tokens.

    Unlike :class:`PageIterator`, this iterator threads the server-provided
    ``next_cursor`` token through the traversal, which is required for the
    deterministic ordering-key cursors used by the finops and cross-contract
    modules.  Traversal stops when ``next_cursor`` is ``None`` or empty.

    Args:
        fetch_fn: Callable with signature
            ``(cursor, limit, filters) -> Page[T]``.  The returned page must
            expose a ``next_cursor`` attribute.
        limit: Items per page (clamped to :data:`MAX_PAGE_LIMIT`).
        filters: Optional :class:`QueryFilters` applied to every page.
        start_cursor: Optional cursor to resume from.

    Example::

        filters = QueryFilters(status="pending", submitter=addr)
        for page in FilteredPageIterator(client.get_finops, 50, filters):
            for record in page.items:
                process(record)
    """

    def __init__(
        self,
        fetch_fn: Callable[..., Page[T]],
        limit: int = 50,
        filters: Optional[QueryFilters] = None,
        start_cursor: Optional[str] = None,
    ) -> None:
        self._fetch = fetch_fn
        self._limit = clamp_limit(limit)
        self._filters = filters
        self._cursor = start_cursor
        self._exhausted = False
        self._pages_fetched = 0

    def __iter__(self) -> Iterator[Page[T]]:
        return self

    def __next__(self) -> Page[T]:
        if self._exhausted:
            raise StopIteration

        page: Page[T] = self._fetch(self._cursor, self._limit, self._filters)
        self._pages_fetched += 1

        next_cursor = getattr(page, "next_cursor", None)
        if not page.items and not next_cursor:
            self._exhausted = True
            raise StopIteration

        self._cursor = next_cursor
        if not next_cursor:
            self._exhausted = True

        return page

    @property
    def cursor(self) -> Optional[str]:
        """The cursor that will be used for the next fetch."""
        return self._cursor

    @property
    def pages_fetched(self) -> int:
        """Number of pages fetched so far."""
        return self._pages_fetched

    def reset(self, start_cursor: Optional[str] = None) -> None:
        """Reset the iterator to the beginning (or *start_cursor*)."""
        self._cursor = start_cursor
        self._exhausted = False
        self._pages_fetched = 0


def iter_filtered_items(
    fetch_fn: Callable[..., Page[T]],
    limit: int = 50,
    filters: Optional[QueryFilters] = None,
    start_cursor: Optional[str] = None,
) -> Iterator[T]:
    """Yield every individual item across all filtered pages.

    Args:
        fetch_fn: Callable with signature
            ``(cursor, limit, filters) -> Page[T]``.
        limit: Items per page (clamped to :data:`MAX_PAGE_LIMIT`).
        filters: Optional :class:`QueryFilters` applied to every page.
        start_cursor: Optional cursor to resume from.

    Yields:
        Individual items of type ``T``.
    """
    for page in FilteredPageIterator(
        fetch_fn, limit=limit, filters=filters, start_cursor=start_cursor
    ):
        yield from page.items


# ── Item iterator (flattened) ─────────────────────────────────────────────────


def iter_all_items(
    fetch_fn: Callable[[int, int], Page[T]],
    limit: int = 50,
    start_offset: int = 0,
) -> Iterator[T]:
    """Yield every individual item across all pages.

    Args:
        fetch_fn: Callable with signature ``(offset, limit) -> Page[T]``.
        limit: Items per page.
        start_offset: Initial offset (default ``0``).

    Yields:
        Individual items of type ``T``.

    Example::

        for event in iter_all_items(client.get_events, limit=100):
            print(event.event_type)
    """
    for page in PageIterator(fetch_fn, limit=limit, start_offset=start_offset):
        yield from page.items


# ── Cursor-based fetch helper ─────────────────────────────────────────────────


def fetch_page_by_cursor(
    fetch_fn: Callable[[int, int], Page[T]],
    cursor: Optional[str],
    limit: int = 50,
) -> Page[T]:
    """Fetch a single page using an opaque cursor.

    Args:
        fetch_fn: Callable with signature ``(offset, limit) -> Page[T]``.
        cursor: Opaque cursor from a previous response, or ``None`` to start
            from the beginning.
        limit: Maximum number of items to return.

    Returns:
        A :class:`~audit_ledger.models.Page` of items.

    Raises:
        ValueError: If the cursor is malformed.
    """
    offset = decode_cursor(cursor) if cursor is not None else 0
    return fetch_fn(offset, clamp_limit(limit))


def fetch_filtered_page(
    fetch_fn: Callable[..., Page[T]],
    cursor: Optional[str] = None,
    limit: int = 50,
    filters: Optional[QueryFilters] = None,
) -> Page[T]:
    """Fetch a single filtered page using an opaque ``next_cursor`` token.

    Args:
        fetch_fn: Callable with signature
            ``(cursor, limit, filters) -> Page[T]``.
        cursor: Opaque cursor from a previous response, or ``None`` to start
            from the beginning.
        limit: Maximum number of items to return (clamped to
            :data:`MAX_PAGE_LIMIT`).
        filters: Optional :class:`QueryFilters` applied to the query.

    Returns:
        A :class:`~audit_ledger.models.Page` of items.
    """
    return fetch_fn(cursor, clamp_limit(limit), filters)


def collect_all_filtered(
    fetch_fn: Callable[..., Page[T]],
    limit: int = 50,
    filters: Optional[QueryFilters] = None,
    start_cursor: Optional[str] = None,
    max_items: Optional[int] = None,
) -> "list[T]":
    """Collect items across all filtered pages into a single list.

    Args:
        fetch_fn: Callable with signature
            ``(cursor, limit, filters) -> Page[T]``.
        limit: Items per page (clamped to :data:`MAX_PAGE_LIMIT`).
        filters: Optional :class:`QueryFilters` applied to every page.
        start_cursor: Optional cursor to resume from.
        max_items: Optional cap on the total number of items collected.

    Returns:
        A list of items in deterministic order.
    """
    items: "list[T]" = []
    for item in iter_filtered_items(
        fetch_fn, limit=limit, filters=filters, start_cursor=start_cursor
    ):
        items.append(item)
        if max_items is not None and len(items) >= max_items:
            break
    return items


def fetch_page_by_composite_cursor(
    fetch_fn: Callable[[Optional[CompositeCursor], int], Page[T]],
    cursor: Optional[str],
    limit: int = 50,
) -> Page[T]:
    """Fetch a single page using a composite ordering-key cursor.

    This is the binding for the cursor token format emitted by
    ``src/cbdc_privacy.rs``.

    Args:
        fetch_fn: Callable with signature ``(cursor, limit) -> Page[T]`` where
            *cursor* is a :class:`CompositeCursor` or ``None`` for the first
            page.
        cursor: Opaque composite cursor from a previous response, or ``None``
            to start from the beginning.
        limit: Maximum number of items to return (clamped to
            :data:`MAX_PAGE_LIMIT`).

    Returns:
        A :class:`~audit_ledger.models.Page` of items.

    Raises:
        ValueError: If the cursor is malformed.
    """
    decoded = decode_composite_cursor(cursor) if cursor is not None else None
    return fetch_fn(decoded, clamp_page_limit(limit))


def iter_pages_by_composite_cursor(
    fetch_fn: Callable[[Optional[CompositeCursor], int], Page[T]],
    limit: int = 50,
    start_cursor: Optional[str] = None,
) -> Iterator[Page[T]]:
    """Iterate over every page using composite cursor traversal.

    Traversal stops when the server returns no ``next_cursor`` or an empty
    page, so it terminates correctly for empty results and single-item pages.

    Args:
        fetch_fn: Callable with signature ``(cursor, limit) -> Page[T]``.
        limit: Items per page (clamped to :data:`MAX_PAGE_LIMIT`).
        start_cursor: Optional cursor to resume from.

    Yields:
        Each :class:`~audit_ledger.models.Page` in order.
    """
    limit = clamp_page_limit(limit)
    cursor: Optional[str] = start_cursor
    while True:
        page = fetch_page_by_composite_cursor(fetch_fn, cursor, limit)
        if not page.items:
            return
        yield page
        cursor = getattr(page, "next_cursor", None)
        if cursor is None:
            return


def iter_all_items_by_composite_cursor(
    fetch_fn: Callable[[Optional[CompositeCursor], int], Page[T]],
    limit: int = 50,
    start_cursor: Optional[str] = None,
) -> Iterator[T]:
    """Yield every individual item across all composite-cursor pages.

    Args:
        fetch_fn: Callable with signature ``(cursor, limit) -> Page[T]``.
        limit: Items per page (clamped to :data:`MAX_PAGE_LIMIT`).
        start_cursor: Optional cursor to resume from.

    Yields:
        Individual items of type ``T``.
    """
    for page in iter_pages_by_composite_cursor(
        fetch_fn, limit=limit, start_cursor=start_cursor
    ):
        yield from page.items


# ── SupTech rule query pagination ─────────────────────────────────────────────


class RuleStatus(str, Enum):
    """Lifecycle status of a SupTech rule evaluation."""

    PENDING = "pending"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class RuleQueryFilter:
    """Multi-predicate filter for SupTech rule queries.

    Attributes:
        ledger_timestamp_min: Inclusive lower bound on the ledger timestamp.
        ledger_timestamp_max: Inclusive upper bound on the ledger timestamp.
        status: Restrict results to a single :class:`RuleStatus`.
        submitter: Restrict results to a single submitter address.
    """

    ledger_timestamp_min: Optional[int] = None
    ledger_timestamp_max: Optional[int] = None
    status: Optional[RuleStatus] = None
    submitter: Optional[str] = None

    def to_query_params(self) -> dict:
        """Render the filter as a flat mapping of query parameters.

        ``None`` fields are omitted so the resulting mapping can be passed
        directly to the SDK's RPC layer.
        """
        params: dict = {}
        if self.ledger_timestamp_min is not None:
            params["ledger_timestamp_min"] = self.ledger_timestamp_min
        if self.ledger_timestamp_max is not None:
            params["ledger_timestamp_max"] = self.ledger_timestamp_max
        if self.status is not None:
            params["status"] = self.status.value
        if self.submitter is not None:
            params["submitter"] = self.submitter
        return params


def encode_rule_cursor(offset: int) -> str:
    """Encode an offset into an opaque SupTech rule query cursor.

    Args:
        offset: Zero-based item index.

    Returns:
        An opaque cursor string.

    Raises:
        ValueError: If *offset* is negative.
    """
    if offset < 0:
        raise ValueError(f"Cursor offset must be non-negative, got {offset}")
    return f"rule:{offset}"


def decode_rule_cursor(cursor: str) -> int:
    """Decode a cursor produced by :func:`encode_rule_cursor`.

    Args:
        cursor: Cursor string previously returned by
            :func:`encode_rule_cursor`.

    Returns:
        The decoded offset integer.

    Raises:
        ValueError: If the cursor is malformed.
    """
    if not isinstance(cursor, str) or not cursor.startswith("rule:"):
        raise ValueError(f"Invalid rule cursor: {cursor!r}")
    try:
        value = int(cursor[len("rule:") :])
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid rule cursor: {cursor!r}") from exc
    if value < 0:
        raise ValueError(f"Cursor offset must be non-negative, got {value}")
    return value


def _clamp_limit(limit: int) -> int:
    """Clamp *limit* to the ``[1, MAX_PAGE_LIMIT]`` range."""
    if limit < 1:
        raise ValueError(f"Page limit must be at least 1, got {limit}")
    return min(limit, MAX_PAGE_LIMIT)


def fetch_rule_page_by_cursor(
    fetch_fn: Callable[..., Page[T]],
    cursor: Optional[str] = None,
    limit: int = 50,
    filters: Optional[RuleQueryFilter] = None,
) -> Page[T]:
    """Fetch a single page of SupTech rule results using an opaque cursor.

    Args:
        fetch_fn: Callable invoked as
            ``fetch_fn(offset, limit, **filter_params) -> Page[T]``.
        cursor: Opaque cursor from a previous response, or ``None`` to start
            from the beginning.
        limit: Maximum number of items to return (capped at
            :data:`MAX_PAGE_LIMIT`).
        filters: Optional :class:`RuleQueryFilter` predicates.

    Returns:
        A :class:`~audit_ledger.models.Page` of items.

    Raises:
        ValueError: If the cursor is malformed or *limit* is invalid.
    """
    offset = decode_rule_cursor(cursor) if cursor is not None else 0
    params = filters.to_query_params() if filters is not None else {}
    return fetch_fn(offset, _clamp_limit(limit), **params)


def iter_rule_pages(
    fetch_fn: Callable[..., Page[T]],
    limit: int = 50,
    filters: Optional[RuleQueryFilter] = None,
) -> Iterator[Page[T]]:
    """Yield every page of SupTech rule results via cursor traversal.

    Traversal stops when a page reports no ``next_cursor`` or returns no
    items, guaranteeing termination even if the backend misbehaves.

    Args:
        fetch_fn: Callable invoked as
            ``fetch_fn(offset, limit, **filter_params) -> Page[T]``.
        limit: Items per page (capped at :data:`MAX_PAGE_LIMIT`).
        filters: Optional :class:`RuleQueryFilter` predicates.

    Yields:
        Successive :class:`~audit_ledger.models.Page` objects.
    """
    cursor: Optional[str] = None
    while True:
        page = fetch_rule_page_by_cursor(
            fetch_fn, cursor=cursor, limit=limit, filters=filters
        )
        if not page.items:
            return
        yield page
        next_cursor = getattr(page, "next_cursor", None)
        if not next_cursor:
            return
        cursor = next_cursor


def iter_all_rule_items(
    fetch_fn: Callable[..., Page[T]],
    limit: int = 50,
    filters: Optional[RuleQueryFilter] = None,
) -> Iterator[T]:
    """Yield every individual SupTech rule item across all pages.

    Args:
        fetch_fn: Callable invoked as
            ``fetch_fn(offset, limit, **filter_params) -> Page[T]``.
        limit: Items per page (capped at :data:`MAX_PAGE_LIMIT`).
        filters: Optional :class:`RuleQueryFilter` predicates.

    Yields:
        Individual rule items of type ``T``.
    """
    for page in iter_rule_pages(fetch_fn, limit=limit, filters=filters):
        yield from page.items
