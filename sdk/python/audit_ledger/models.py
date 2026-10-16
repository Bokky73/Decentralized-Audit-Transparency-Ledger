"""Data models and exception types for the AuditLedger Python SDK."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Generic, List, Optional, TypeVar

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
# Generic pagination container
# ---------------------------------------------------------------------------


@dataclass
class Page(Generic[T]):
    """A paginated result set.

    Attributes:
        items: The events on this page.
        total: Total number of events available.
        offset: Zero-based index of the first item on this page.
        limit: Maximum number of items requested per page.
        next_cursor: Opaque cursor token for fetching the next page, or
            ``None`` when this is the last page.
    """

    items: List[T]
    total: int
    offset: int
    limit: int
    next_cursor: Optional[str] = None


# ---------------------------------------------------------------------------
# Cursor-based pagination and filtering surface (#852)
# ---------------------------------------------------------------------------


@dataclass
class PageCursor:
    """Opaque cursor token identifying a position in a deterministic ordering.

    Attributes:
        token: The raw cursor token returned by the contract as
            ``next_cursor``.  ``None`` denotes the start of the result set.
    """

    token: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        """Serialise the cursor for inclusion in a contract query request."""
        return {"cursor": self.token}


@dataclass
class PageLimit:
    """A validated page-size request.

    The value is clamped to ``[1, MAX_PAGE_LIMIT]`` so that a single
    invocation can never exhaust the Soroban CPU/memory budget.

    Attributes:
        value: The effective, clamped page size.
    """

    value: int = DEFAULT_PAGE_LIMIT

    def __post_init__(self) -> None:
        if self.value < 1:
            self.value = 1
        elif self.value > MAX_PAGE_LIMIT:
            self.value = MAX_PAGE_LIMIT

    def to_dict(self) -> Dict[str, object]:
        """Serialise the limit for inclusion in a contract query request."""
        return {"limit": self.value}


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
