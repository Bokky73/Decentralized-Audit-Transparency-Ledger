import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AuditLedgerClient } from '../AuditLedgerClient';
import { AuditLedgerError, Event } from '../types';

function makeEvent(index: number): Event {
  return {
    index,
    timestamp: 1_700_000_000 + index,
    event_type: 'payment',
    submitter: index % 2 === 0 ? 'GABC' : 'GXYZ',
    metadata: `payload-${index}`,
    event_hash: '00'.repeat(32),
    prev_hash: '11'.repeat(32),
  };
}

describe('AuditLedgerClient', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('calls transport for totalEvents', async () => {
    const transport = async (method: string, _params: unknown[]) => {
      if (method === 'total_events') return 42;
      return null;
    };
    const c = new AuditLedgerClient(transport);
    const total = await c.totalEvents();
    expect(total).toBe(42);
  });

  it('calls transport for logEvents', async () => {
    const transport = async (method: string, _params: unknown[]) => {
      if (method === 'log_events') return [0, 1, 2];
      return null;
    };
    const c = new AuditLedgerClient(transport);
    const indices = await c.logEvents([
      { submitter: 'GABC', type: 'payment', metadata: 'data' },
    ]);
    expect(indices).toEqual([0, 1, 2]);
  });

  it('retries network errors with exponential backoff', async () => {
    const transport = vi.fn()
      .mockRejectedValueOnce(new TypeError('network down'))
      .mockRejectedValueOnce(new TypeError('still down'))
      .mockResolvedValueOnce(42);

    const c = new AuditLedgerClient(transport);
    const promise = c.totalEvents();

    await vi.advanceTimersByTimeAsync(500);
    await vi.advanceTimersByTimeAsync(1000);

    await expect(promise).resolves.toBe(42);
    expect(transport).toHaveBeenCalledTimes(3);
  });

  it('retries 429 and stops after maxRetries', async () => {
    const transport = vi.fn()
      .mockRejectedValueOnce(new AuditLedgerError('rate limited', undefined, 429))
      .mockRejectedValueOnce(new AuditLedgerError('still limited', undefined, 429))
      .mockResolvedValueOnce(7);

    const c = new AuditLedgerClient(transport, undefined, { maxRetries: 2, baseDelayMs: 25 });
    const promise = c.eventCount('payment');

    await vi.advanceTimersByTimeAsync(25);
    await vi.advanceTimersByTimeAsync(50);

    await expect(promise).resolves.toBe(7);
    expect(transport).toHaveBeenCalledTimes(3);
  });

  it('does not retry non-retryable status codes', async () => {
    const transport = vi.fn().mockRejectedValue(new AuditLedgerError('bad request', undefined, 400));
    const c = new AuditLedgerClient(transport, undefined, { maxRetries: 3, baseDelayMs: 10 });

    await expect(c.getEvent('1')).rejects.toThrow('bad request');
    expect(transport).toHaveBeenCalledTimes(1);
  });

  it('supports paginated retrieval with cursor-based offsets', async () => {
    const transport = vi.fn().mockImplementation(async (method: string, params: unknown[]) => {
      if (method === 'total_events') return 5;
      if (method === 'get_event_by_order') return makeEvent(params[0] as number);
      return null;
    });
    const client = new AuditLedgerClient(transport);
    const page = await client.getEvents(0, 3, 2);
    expect(page.items.map((event: Event) => event.index)).toEqual([2, 3, 4]);
    expect(page.offset).toBe(2);
  });

  it('filters and exports events', () => {
    const client = new AuditLedgerClient(async () => null);
    const events = [makeEvent(0), makeEvent(1), makeEvent(2)];
    const filtered = client.filterEvents(events, { eventType: 'payment', submitter: 'GABC', metadataQuery: '0' });
    expect(filtered.map((event) => event.index)).toEqual([0]);
    const csv = client.exportEvents([events[0]], 'csv');
    expect(csv.startsWith('index,timestamp')).toBe(true);
    const json = client.exportEvents([events[0]], 'json');
    expect(JSON.parse(json)[0].event_type).toBe('payment');
  });

  it('streams events with progress updates', async () => {
    const transport = vi.fn().mockImplementation(async (method: string, params: unknown[]) => {
      if (method === 'total_events') return 2;
      if (method === 'get_event_by_order') return makeEvent(params[0] as number);
      return null;
    });
    const client = new AuditLedgerClient(transport);
    const progress: Array<{ completed: number; total: number }> = [];
    const exported = client.exportEvents([makeEvent(0), makeEvent(1)], 'json', true, (p) => progress.push(p));
    expect(JSON.parse(exported).length).toBe(2);
    expect(progress[progress.length - 1]).toEqual({ completed: 2, total: 2 });
  });

  it('tracks cache hits and invalidates cache entries', async () => {
    const transport = vi.fn().mockImplementation(async (method: string, params: any[]) => {
      if (method === 'get_event_by_order') return makeEvent(params[0]);
      return null;
    });
    const client = new AuditLedgerClient(transport);
    await client.getEventByOrder(0);
    await client.getEventByOrder(0);
    const stats = client.cacheStats();
    expect(stats.hits).toBe(1);
    expect(stats.size).toBe(1);
    client.invalidateCache();
    expect(client.cacheStats().size).toBe(0);
  });

  describe('paginated finops queries', () => {
    interface FinOpsRecord {
      id: number;
      ledger_timestamp: number;
      status: string;
      submitter: string;
    }

    function makeFinOpsRecord(id: number): FinOpsRecord {
      return {
        id,
        ledger_timestamp: 1_700_000_000 + id,
        status: id % 3 === 0 ? 'settled' : id % 3 === 1 ? 'pending' : 'failed',
        submitter: id % 2 === 0 ? 'GABC' : 'GXYZ',
      };
    }

    function makeFinOpsTransport(records: FinOpsRecord[]) {
      return vi.fn().mockImplementation(async (method: string, params: any[]) => {
        if (method === 'query_finops') {
          const { cursor, limit, status, submitter, from_timestamp, to_timestamp } = params[0] ?? {};
          const cap = Math.min(limit ?? 100, 100);
          let filtered = records.slice();
          if (status !== undefined && status !== null) {
            filtered = filtered.filter((r) => r.status === status);
          }
          if (submitter !== undefined && submitter !== null) {
            filtered = filtered.filter((r) => r.submitter === submitter);
          }
          if (from_timestamp !== undefined && from_timestamp !== null) {
            filtered = filtered.filter((r) => r.ledger_timestamp >= from_timestamp);
          }
          if (to_timestamp !== undefined && to_timestamp !== null) {
            filtered = filtered.filter((r) => r.ledger_timestamp <= to_timestamp);
          }
          const start = cursor === undefined || cursor === null ? 0 : Number(cursor);
          const page = filtered.slice(start, start + cap);
          const next = start + page.length < filtered.length ? String(start + page.length) : null;
          return { items: page, next_cursor: next };
        }
        return null;
      });
    }

    it('returns empty results with a null next_cursor', async () => {
      const client = new AuditLedgerClient(makeFinOpsTransport([]));
      const page = await client.queryFinOps({ limit: 10 });
      expect(page.items).toEqual([]);
      expect(page.next_cursor).toBeNull();
    });

    it('returns a single-item page and terminates traversal', async () => {
      const client = new AuditLedgerClient(makeFinOpsTransport([makeFinOpsRecord(0)]));
      const page = await client.queryFinOps({ limit: 1 });
      expect(page.items.map((r) => r.id)).toEqual([0]);
      expect(page.next_cursor).toBeNull();
    });

    it('returns a null next_cursor when the cursor is past the end', async () => {
      const client = new AuditLedgerClient(makeFinOpsTransport([makeFinOpsRecord(0), makeFinOpsRecord(1)]));
      const page = await client.queryFinOps({ cursor: '99', limit: 10 });
      expect(page.items).toEqual([]);
      expect(page.next_cursor).toBeNull();
    });

    it('traverses all pages deterministically', async () => {
      const records = Array.from({ length: 7 }, (_, i) => makeFinOpsRecord(i));
      const client = new AuditLedgerClient(makeFinOpsTransport(records));
      const seen: number[] = [];
      let cursor: string | null = null;
      let pages = 0;
      do {
        const page = await client.queryFinOps({ cursor, limit: 3 });
        seen.push(...page.items.map((r) => r.id));
        cursor = page.next_cursor;
        pages += 1;
      } while (cursor !== null);
      expect(seen).toEqual([0, 1, 2, 3, 4, 5, 6]);
      expect(pages).toBe(3);
    });

    it('caps the page limit at 100 items', async () => {
      const records = Array.from({ length: 150 }, (_, i) => makeFinOpsRecord(i));
      const client = new AuditLedgerClient(makeFinOpsTransport(records));
      const page = await client.queryFinOps({ limit: 500 });
      expect(page.items.length).toBe(100);
      expect(page.next_cursor).toBe('100');
    });

    it('filters by status, submitter and timestamp range', async () => {
      const records = Array.from({ length: 9 }, (_, i) => makeFinOpsRecord(i));
      const client = new AuditLedgerClient(makeFinOpsTransport(records));

      const byStatus = await client.queryFinOps({ status: 'settled', limit: 100 });
      expect(byStatus.items.every((r) => r.status === 'settled')).toBe(true);

      const bySubmitter = await client.queryFinOps({ submitter: 'GABC', limit: 100 });
      expect(bySubmitter.items.every((r) => r.submitter === 'GABC')).toBe(true);

      const byRange = await client.queryFinOps({
        from_timestamp: 1_700_000_002,
        to_timestamp: 1_700_000_004,
        limit: 100,
      });
      expect(byRange.items.map((r) => r.id)).toEqual([2, 3, 4]);

      const combined = await client.queryFinOps({
        status: 'pending',
        submitter: 'GABC',
        limit: 100,
      });
      expect(combined.items.every((r) => r.status === 'pending' && r.submitter === 'GABC')).toBe(true);
    });
  });

  describe('paginated cross-contract queries', () => {
    interface CrossContractRecord {
      id: number;
      ledger_timestamp: number;
      status: string;
      submitter: string;
    }

    function makeCrossContractRecord(id: number): CrossContractRecord {
      return {
        id,
        ledger_timestamp: 1_700_000_000 + id,
        status: id % 3 === 0 ? 'settled' : id % 3 === 1 ? 'pending' : 'failed',
        submitter: id % 2 === 0 ? 'GABC' : 'GXYZ',
      };
    }

    function makeCrossContractTransport(records: CrossContractRecord[]) {
      return vi.fn().mockImplementation(async (method: string, params: any[]) => {
        if (method === 'query_cross_contract') {
          const { cursor, limit, status, submitter, from_timestamp, to_timestamp } = params[0] ?? {};
          const cap = Math.min(limit ?? 100, 100);
          let filtered = records.slice();
          if (status !== undefined && status !== null) {
            filtered = filtered.filter((r) => r.status === status);
          }
          if (submitter !== undefined && submitter !== null) {
            filtered = filtered.filter((r) => r.submitter === submitter);
          }
          if (from_timestamp !== undefined && from_timestamp !== null) {
            filtered = filtered.filter((r) => r.ledger_timestamp >= from_timestamp);
          }
          if (to_timestamp !== undefined && to_timestamp !== null) {
            filtered = filtered.filter((r) => r.ledger_timestamp <= to_timestamp);
          }
          const start = cursor === undefined || cursor === null ? 0 : Number(cursor);
          const page = filtered.slice(start, start + cap);
          const next = start + page.length < filtered.length ? String(start + page.length) : null;
          return { items: page, next_cursor: next };
        }
        return null;
      });
    }

    it('returns empty results with a null next_cursor', async () => {
      const client = new AuditLedgerClient(makeCrossContractTransport([]));
      const page = await client.queryCrossContract({ limit: 10 });
      expect(page.items).toEqual([]);
      expect(page.next_cursor).toBeNull();
    });

    it('returns a single-item page and terminates traversal', async () => {
      const client = new AuditLedgerClient(makeCrossContractTransport([makeCrossContractRecord(0)]));
      const page = await client.queryCrossContract({ limit: 1 });
      expect(page.items.map((r) => r.id)).toEqual([0]);
      expect(page.next_cursor).toBeNull();
    });

    it('returns a null next_cursor when the cursor is past the end', async () => {
      const client = new AuditLedgerClient(
        makeCrossContractTransport([makeCrossContractRecord(0), makeCrossContractRecord(1)]),
      );
      const page = await client.queryCrossContract({ cursor: '99', limit: 10 });
      expect(page.items).toEqual([]);
      expect(page.next_cursor).toBeNull();
    });

    it('traverses all pages deterministically', async () => {
      const records = Array.from({ length: 7 }, (_, i) => makeCrossContractRecord(i));
      const client = new AuditLedgerClient(makeCrossContractTransport(records));
      const seen: number[] = [];
      let cursor: string | null = null;
      let pages = 0;
      do {
        const page = await client.queryCrossContract({ cursor, limit: 3 });
        seen.push(...page.items.map((r) => r.id));
        cursor = page.next_cursor;
        pages += 1;
      } while (cursor !== null);
      expect(seen).toEqual([0, 1, 2, 3, 4, 5, 6]);
      expect(pages).toBe(3);
    });

    it('caps the page limit at 100 items', async () => {
      const records = Array.from({ length: 150 }, (_, i) => makeCrossContractRecord(i));
      const client = new AuditLedgerClient(makeCrossContractTransport(records));
      const page = await client.queryCrossContract({ limit: 500 });
      expect(page.items.length).toBe(100);
      expect(page.next_cursor).toBe('100');
    });

    it('filters by status, submitter and timestamp range', async () => {
      const records = Array.from({ length: 9 }, (_, i) => makeCrossContractRecord(i));
      const client = new AuditLedgerClient(makeCrossContractTransport(records));

      const byStatus = await client.queryCrossContract({ status: 'settled', limit: 100 });
      expect(byStatus.items.every((r) => r.status === 'settled')).toBe(true);

      const bySubmitter = await client.queryCrossContract({ submitter: 'GABC', limit: 100 });
      expect(bySubmitter.items.every((r) => r.submitter === 'GABC')).toBe(true);

      const byRange = await client.queryCrossContract({
        from_timestamp: 1_700_000_002,
        to_timestamp: 1_700_000_004,
        limit: 100,
      });
      expect(byRange.items.map((r) => r.id)).toEqual([2, 3, 4]);

      const combined = await client.queryCrossContract({
        status: 'pending',
        submitter: 'GABC',
        limit: 100,
      });
      expect(combined.items.every((r) => r.status === 'pending' && r.submitter === 'GABC')).toBe(true);
    });
  });
});
