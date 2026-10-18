/** Hex or base64 encoded 32-byte hash string. */
export type Bytes32 = string;

/** Hex or base64 encoded byte payload. */
export type Bytes = string;

export interface Event {
  index: number;
  timestamp: number;
  event_type: string;
  submitter: string;
  metadata: string;
  event_hash: Bytes32;
  prev_hash: Bytes32;
}

export interface EventHeader {
  index: number;
  timestamp: number;
  event_type: string;
  submitter: string;
}

export interface NonceState {
  last_nonce: number;
  window_size: number;
  max_nonce: number;
}

export interface SnapshotMetadata {
  id: number;
  timestamp: number;
  event_count: number;
  event_hash: Bytes32;
  description: string;
}

export interface ContractStatistics {
  total_events: number;
  events_by_type: Array<[string, number]>;
  events_last_hour: number;
  events_last_day: number;
  events_last_week: number;
  top_submitters: Array<[string, number]>;
}

export interface EventPage {
  items: Event[];
  total: number;
  offset: number;
  limit: number;
}

/**
 * Opaque cursor token for deterministic cursor-based pagination.
 *
 * Pass the `next_cursor` returned by a previous page back into the next
 * query to fetch the following page. `null`/`undefined` requests the first
 * page; a `null` `next_cursor` in a response means the end was reached.
 */
export type PageCursor = string;

/** Maximum number of items a single page may contain (capped at 100). */
export const MAX_PAGE_LIMIT = 100;

/** Requested page size, capped at {@link MAX_PAGE_LIMIT}. */
export type PageLimit = number;

/** Status enum used to filter FinOps, cross-contract, and privacy query results. */
export enum QueryStatus {
  Pending = 0,
  Success = 1,
  Active = 1,
  Failed = 2,
  Archived = 2,
  Cancelled = 3,
  Revoked = 3,
}

/** Inclusive ledger timestamp range filter. */
export interface TimestampRangeFilter {
  /** Inclusive lower bound (ledger timestamp, seconds). */
  from?: number;
  /** Inclusive upper bound (ledger timestamp, seconds). */
  to?: number;
}

/** Multi-predicate filter shared by all paginated collection queries. */
export interface QueryFilter {
  /** Filter by ledger timestamp range. */
  timestamp?: TimestampRangeFilter;
  /** Inclusive lower bound on ledger timestamp. */
  timestamp_from?: number;
  /** Inclusive upper bound on ledger timestamp. */
  timestamp_to?: number;
  /** Filter by record status. */
  status?: QueryStatus;
  /** Filter by submitter address. */
  submitter?: string;
}

/** Pagination request options shared by all paginated collection queries. */
export interface PageQuery extends QueryFilter {
  /** Cursor from a previous page; omit for the first page. */
  cursor?: PageCursor;
  /** Requested page size; capped at {@link MAX_PAGE_LIMIT}. */
  limit?: PageLimit;
}

/** Generic paginated result carrying the page items and the next cursor. */
export interface Page<T> {
  items: T[];
  /** Cursor for the next page, or `null` when the end has been reached. */
  next_cursor: PageCursor | null;
}

/** Paginated query result carrying a cursor for the next page. Alias for {@link Page}. */
export type PaginatedResult<T = Event> = Page<T>;

/** Status of a SupTech rule. */
export enum RuleStatus {
  Active = 'Active',
  Inactive = 'Inactive',
  Pending = 'Pending',
  Suspended = 'Suspended',
}

/** Multi-predicate filter for SupTech rule queries. */
export interface RuleQueryFilter {
  /** Inclusive lower bound on ledger timestamp. */
  ledger_timestamp_min?: number;
  /** Inclusive upper bound on ledger timestamp. */
  ledger_timestamp_max?: number;
  /** Restrict results to a single rule status. */
  status?: RuleStatus;
  /** Restrict results to a single submitter address. */
  submitter?: string;
}

/** A single page of SupTech rule query results. */
export interface RulePage {
  items: Event[];
  /** Cursor to pass to the next query, or null when the end has been reached. */
  next_cursor: PageCursor | null;
}
export interface CacheStats {
  hits: number;
  misses: number;
  size: number;
}

export enum ContractError {
  CallerNotOwner = 1,
  GlobalMaxLogsReached = 2,
  EventTypeMaxLogsReached = 3,
  EventDoesNotExist = 4,
  EventTypeIndexOutOfBounds = 5,
  NewOwnerIsZero = 6,
  CapNotSet = 7,
  MetadataTooLarge = 8,
  InvalidSignature = 9,
  ContractPaused = 10,
  RateLimitExceeded = 11,
  NoEventsForType = 14,
  AlreadyInitialized = 15,
}

export class AuditLedgerError extends Error {
  code?: number;
  status?: number;
  /** Seconds to wait before retrying, parsed from a `Retry-After` response header, if present. */
  retryAfterSeconds?: number;
  constructor(message: string, code?: number, status?: number, retryAfterSeconds?: number) {
    super(message);
    this.name = 'AuditLedgerError';
    this.code = code;
    this.status = status;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/** Batch signing types (issue #218). */
export interface SignedEvent {
  event_type: string;
  submitter: string;
  metadata: string;
  timestamp: number;
  nonce: number;
}

export interface BatchSignature {
  /** Public key of the signer (hex-encoded Ed25519 pubkey). */
  pubkey: string;
  /** Ed25519 signature over the SHA-256 of the concatenated event hashes. */
  signature: string;
  /** Number of events covered by this batch signature. */
  event_count: number;
  /** SHA-256 hash of the concatenated event preimages. */
  batch_hash: Bytes32;
}

export interface BatchVerificationResult {
  valid: boolean;
  event_count: number;
  batch_hash: Bytes32;
  error?: string;
}
