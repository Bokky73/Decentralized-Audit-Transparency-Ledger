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

#: Maximum number of items a single page may request (mirrors the on-chain cap
#: enforced by ``src/cbdc_privacy.rs``).
MAX_PAGE_LIMIT = 100

#: Separator used by the on-chain composite cursor encoding.
_CURSOR_SEPARATOR = ":"

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


def clamp_page_limit(limit: int) -> int:
    """Clamp *limit* to the on-chain maximum page size.

    Args:
        limit: Requested page size.

    Returns:
        ``limit`` clamped to ``[1, MAX_PAGE_LIMIT]``.

    Raises:
        ValueError: If *limit* is not a positive integer.
    """
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise ValueError(f"Page limit must be a positive integer, got {limit!r}")
    return min(limit, MAX_PAGE_LIMIT)


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
    return fetch_fn(offset, clamp_page_limit(limit))


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
