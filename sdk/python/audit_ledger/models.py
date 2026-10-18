"""Data models and exception types for the AuditLedger Python SDK."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Generic, List, Optional, TypeVar, Union

# ---------------------------------------------------------------------------
# Pagination constants (#852)
# ---------------------------------------------------------------------------

MAX_PAGE_LIMIT = 100
"""Hard cap on the number of items returned by a single paginated query."""

DEFAULT_PAGE_LIMIT = 20
"""Default page size used when the caller does not supply a limit."""

# ---------------------------------------------------------------------------
# Type aliases (#243)
# ---------------------------------------------------------------------------

EventId = bytes
"""32-byte content-addressed event identifier."""

EventType = str
"""Symbolic event type string (e.g. ``"payment"``, ``"refund"``)."""

Address = str
"""Stellar account address (G... string)."""

Metadata = bytes
"""Raw binary metadata attached to an event."""

ErrorCode = int
"""Integer error code returned by the contract."""

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Cursor-based pagination primitives (#862, #867)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PageCursor:
    """Opaque, deterministic cursor marking the start of a page.

    The cursor is derived from the stable ordering key of the last item
    returned by the previous page, so traversal is deterministic across
    ledger upgrades and archival restores.

    Attributes:
        value: Opaque cursor token; ``None`` starts from the beginning.
        token: Alias for ``value``.
    """

    value: Optional[str] = None
    token: Optional[str] = None

    def __post_init__(self) -> None:
        if self.value is None and self.token is not None:
            object.__setattr__(self, "value", self.token)
        elif self.token is None and self.value is not None:
            object.__setattr__(self, "token", self.value)

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, object]]) -> "PageCursor":
        """Build a cursor from a raw contract-response dict.

        Args:
            d: Raw dictionary, or ``None`` for the initial page.

        Returns:
            A :class:`PageCursor` instance.
        """
        if not d:
            return cls()
        raw = d.get("value") if "value" in d else d.get("cursor")
        return cls(value=None if raw is None else str(raw))

    def to_dict(self) -> Dict[str, object]:
        """Serialise the cursor for an RPC request payload."""
        return {"value": self.value, "cursor": self.value}


@dataclass(frozen=True)
class PageLimit:
    """Validated page-size cap.

    Attributes:
        value: Requested number of items per page, clamped to
            ``[1, MAX_PAGE_LIMIT]``.
    """

    value: int = DEFAULT_PAGE_LIMIT

    def __post_init__(self) -> None:
        if self.value < 1:
            raise ValueError("PageLimit must be at least 1")
        if self.value > MAX_PAGE_LIMIT:
            raise ValueError(
                f"PageLimit must not exceed {MAX_PAGE_LIMIT}"
            )

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, object]]) -> "PageLimit":
        """Build a limit from a raw contract-response dict."""
        if not d or (d.get("value") is None and d.get("limit") is None):
            return cls()
        raw = d.get("value") if "value" in d else d.get("limit")
        return cls(value=int(raw))  # type: ignore[arg-type]

    def to_dict(self) -> Dict[str, object]:
        """Serialise the limit for an RPC request payload."""
        return {"value": self.value, "limit": self.value}


class QueryStatus(str, Enum):
    """Status enum used to filter paginated queries."""

    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    ARCHIVED = "archived"


@dataclass(frozen=True)
class QueryFilter:
    """Multi-predicate filter for paginated collection queries.

    All predicates are optional; omitted predicates match every record.

    Attributes:
        start_timestamp: Inclusive lower bound on ledger timestamp.
        end_timestamp: Inclusive upper bound on ledger timestamp.
        status: Optional status enum to match.
        submitter: Optional submitter address to match.
    """

    start_timestamp: Optional[int] = None
    end_timestamp: Optional[int] = None
    status: Optional[QueryStatus] = None
    submitter: Optional[Address] = None

    def __post_init__(self) -> None:
        if (
            self.start_timestamp is not None
            and self.end_timestamp is not None
            and self.start_timestamp > self.end_timestamp
        ):
            raise ValueError(
                "start_timestamp must not be greater than end_timestamp"
            )

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, object]]) -> "QueryFilter":
        """Build a filter from a raw contract-response dict."""
        if not d:
            return cls()

        raw_status = d.get("status")
        status: Optional[QueryStatus]
        if raw_status is None or raw_status == "":
            status = None
        else:
            try:
                status = QueryStatus(str(raw_status))
            except ValueError:
                status = None

        raw_start = d.get("start_timestamp")
        raw_end = d.get("end_timestamp")
        raw_submitter = d.get("submitter")

        return cls(
            start_timestamp=(
                None if raw_start is None else int(raw_start)  # type: ignore[arg-type]
            ),
            end_timestamp=(
                None if raw_end is None else int(raw_end)  # type: ignore[arg-type]
            ),
            status=status,
            submitter=(
                None if raw_submitter in (None, "") else str(raw_submitter)
            ),
        )

    def to_dict(self) -> Dict[str, object]:
        """Serialise the filter for an RPC request payload."""
        return {
            "start_timestamp": self.start_timestamp,
            "end_timestamp": self.end_timestamp,
            "status": None if self.status is None else self.status.value,
            "submitter": self.submitter,
        }


# ---------------------------------------------------------------------------
# Generic pagination container
# ---------------------------------------------------------------------------


@dataclass
class Page(Generic[T]):
    """A cursor-paginated result set.

    Attributes:
        items: The items on this page.
        next_cursor: Cursor to pass to the next request, or ``None`` when
            the traversal is exhausted.
        total: Total number of items available (legacy offset pagination).
        offset: Zero-based index of the first item on this page (legacy).
        limit: Maximum number of items requested per page.
        next_cursor: Opaque cursor token for fetching the next page, or
            ``None`` when this is the last page.
    """

    items: List[T]
    next_cursor: Optional[Union[PageCursor, str]] = None
    total: int = 0
    offset: int = 0
    limit: int = MAX_PAGE_LIMIT

    @property
    def has_more(self) -> bool:
        """Whether another page is available."""
        return self.next_cursor is not None

    @classmethod
    def from_dict(
        cls,
        d: Dict[str, object],
        item_factory: Optional[object] = None,
    ) -> "Page[T]":
        """Build a page from a raw contract-response dict.

        Args:
            d: Raw dictionary from the contract RPC response.
            item_factory: Optional callable converting each raw item dict
                into a model instance.  When omitted, raw dicts are kept.

        Returns:
            A :class:`Page` instance.
        """
        raw_items = d.get("items") or []
        items: List[T] = []
        for raw in raw_items:  # type: ignore[union-attr]
            if item_factory is not None and callable(item_factory):
                items.append(item_factory(raw))  # type: ignore[misc]
            else:
                items.append(raw)  # type: ignore[arg-type]

        raw_cursor = d.get("next_cursor")
        next_cursor: Optional[Union[PageCursor, str]]
        if raw_cursor is None or raw_cursor == "":
            next_cursor = None
        elif isinstance(raw_cursor, dict):
            next_cursor = PageCursor.from_dict(raw_cursor)
        elif isinstance(raw_cursor, PageCursor):
            next_cursor = raw_cursor
        else:
            next_cursor = PageCursor(value=str(raw_cursor))

        return cls(
            items=items,
            next_cursor=next_cursor,
            total=int(d.get("total", len(items))),  # type: ignore[arg-type]
            offset=int(d.get("offset", 0)),  # type: ignore[arg-type]
            limit=int(d.get("limit", MAX_PAGE_LIMIT)),  # type: ignore[arg-type]
        )


# ---------------------------------------------------------------------------
# Multi-predicate event filtering (#852)
# ---------------------------------------------------------------------------


@dataclass
class EventFilter:
    """Multi-predicate filter for paginated event queries.

    All predicates are optional; ``None`` means "no constraint".  When
    several are supplied they are combined with logical AND.

    Attributes:
        start_timestamp: Inclusive lower bound on the ledger timestamp.
        end_timestamp: Inclusive upper bound on the ledger timestamp.
        status: Optional status enum value (e.g. ``"active"``).
        submitter: Optional Stellar address of the event submitter.
    """

    start_timestamp: Optional[int] = None
    end_timestamp: Optional[int] = None
    status: Optional[str] = None
    submitter: Optional[Address] = None

    def to_dict(self) -> Dict[str, object]:
        """Serialise only the predicates that were actually supplied."""
        result: Dict[str, object] = {}
        if self.start_timestamp is not None:
            result["start_timestamp"] = self.start_timestamp
        if self.end_timestamp is not None:
            result["end_timestamp"] = self.end_timestamp
        if self.status is not None:
            result["status"] = self.status
        if self.submitter is not None:
            result["submitter"] = self.submitter
        return result


# ---------------------------------------------------------------------------
# Event model
# ---------------------------------------------------------------------------


@dataclass
class Event:
    """Represents a single audit event stored on-chain.

    Attributes:
        index: Global sequential index of this event.
        timestamp: Unix timestamp (seconds) when the event was recorded.
        event_type: Symbolic event type string.
        submitter: Stellar address of the event submitter.
        metadata: Raw binary metadata attached to the event.
        event_hash: Optional 32-byte content-addressed event ID.
        prev_hash: Optional 32-byte hash of the preceding event in the chain.
    """

    index: int
    timestamp: int
    event_type: EventType
    submitter: Address
    metadata: Metadata
    event_hash: Optional[EventId] = field(default=None)
    prev_hash: Optional[EventId] = field(default=None)

    @classmethod
    def from_dict(cls, d: Dict[str, object]) -> "Event":
        """Construct an :class:`Event` from a raw contract-response dict.

        Missing or empty hash fields are stored as ``None``.  Metadata is
        decoded from a hex string when present; a missing key yields
        ``b""``.

        Args:
            d: Raw dictionary from the contract RPC response.

        Returns:
            A fully-populated :class:`Event` instance.
        """
        raw_event_hash = d.get("event_hash")
        raw_prev_hash = d.get("prev_hash")

        event_hash: Optional[EventId]
        prev_hash: Optional[EventId]

        if raw_event_hash:
            try:
                event_hash = bytes.fromhex(str(raw_event_hash))
            except ValueError:
                event_hash = None
        else:
            event_hash = None

        if raw_prev_hash:
            try:
                prev_hash = bytes.fromhex(str(raw_prev_hash))
            except ValueError:
                prev_hash = None
        else:
            prev_hash = None

        raw_metadata = d.get("metadata", "")
        if raw_metadata:
            try:
                metadata: Metadata = bytes.fromhex(str(raw_metadata))
            except ValueError:
                # Fall back to treating the value as raw bytes / string
                metadata = str(raw_metadata).encode()
        else:
            metadata = b""

        return cls(
            index=int(d["index"]),  # type: ignore[arg-type]
            timestamp=int(d["timestamp"]),  # type: ignore[arg-type]
            event_type=str(d["event_type"]),
            submitter=str(d["submitter"]),
            metadata=metadata,
            event_hash=event_hash,
            prev_hash=prev_hash,
        )


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class AuditLedgerError(Exception):
    """Base exception for all AuditLedger SDK errors."""


class ContractError(AuditLedgerError):
    """Raised when the contract returns a numeric error code.

    Attributes:
        code: The raw contract error code.
        name: Human-readable name for the error code.
    """

    ERROR_CODES: Dict[ErrorCode, str] = {
        1: "CallerNotOwner",
        2: "GlobalMaxLogsReached",
        3: "EventTypeMaxLogsReached",
        4: "EventDoesNotExist",
        5: "EventTypeIndexOutOfBounds",
        6: "NewOwnerIsZero",
        7: "CapNotSet",
        8: "MetadataTooLarge",
        9: "InvalidSignature",
        10: "ContractPaused",
        11: "RateLimitExceeded",
        14: "NoEventsForType",
        15: "AlreadyInitialized",
    }

    def __init__(self, code: ErrorCode) -> None:
        self.code: ErrorCode = code
        self.name: str = self.ERROR_CODES.get(code, f"UnknownError({code})")
        super().__init__(f"ContractError #{code}: {self.name}")


class RPCError(AuditLedgerError):
    """Raised when the Soroban RPC call itself fails (network, timeout, etc.)."""
