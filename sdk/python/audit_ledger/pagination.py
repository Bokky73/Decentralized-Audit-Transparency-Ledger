"""AuditLedger Python SDK — Pagination helpers.

Issue #248: Add cursor-based pagination, page iteration, total count caching,
and pagination state management.
"""

from __future__ import annotations

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

#: Maximum number of items a single SupTech rule query page may return.
MAX_PAGE_LIMIT = 100

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

        self._state.advance(len(page.items))
        return page

    @property
    def state(self) -> PaginationState:
        """The current :class:`PaginationState`."""
        return self._state

    def reset(self) -> None:
        """Reset the iterator to the beginning."""
        self._state.reset()


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
    return fetch_fn(offset, limit)


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
