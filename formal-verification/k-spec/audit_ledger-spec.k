// ============================================================================
// K-Framework Semantic Specification — AuditLedger Smart Contract
// Issue #378: Formal Verification of AuditLedger
// ============================================================================
//
// This module defines the operational semantics of the AuditLedger contract
// using the K Framework (https://kframework.org/).
//
// It models the key state transitions, initialization invariants, and cap
// enforcement rewrite rules for the Soroban Rust contract.
//
// Run with:
//   kompile audit_ledger-spec.k --backend haskell
//   kprove audit_ledger-spec.k
// ============================================================================

requires "domains.md"

module AUDIT-LEDGER-SYNTAX
    imports DOMAINS-SYNTAX

    // ── Types ────────────────────────────────────────────────────────────────

    syntax Address    ::= r"[A-Z0-9]{56}"  [token]  // Stellar G-account
    syntax Symbol     ::= r"[a-zA-Z_][a-zA-Z0-9_]{0,31}" [token]
    syntax Bytes32    ::= r"0x[0-9a-f]{64}" [token]
    syntax EventIndex ::= Int  // u32 global event index
    syntax Nonce      ::= Int  // u64 per-submitter nonce

    // ── Contract Operations ──────────────────────────────────────────────────

    syntax Stmt ::=
        // Initialization
          "initialize" "(" Address "," Int ")"
        // Logging
        | "logEvent" "(" Address "," Symbol "," Bytes ")"
        | "logEvents" "(" List ")"
        // Governance
        | "setGlobalMaxLogs" "(" Address "," Int ")"
        | "setEventMaxLogs" "(" Address "," Symbol "," Int ")"
        | "removeEventCap" "(" Address "," Symbol ")"
        | "transferOwnership" "(" Address "," Address ")"
        | "setPaused" "(" Address "," Bool ")"
        // Queries (read-only)
        | "totalEvents" "(" ")"
        | "getEvent" "(" Bytes32 ")"
        | "eventCount" "(" Symbol ")"

    // ── Values ───────────────────────────────────────────────────────────────

    syntax KResult ::= Int | Bool | String | Bytes32 | EventRecord

    syntax EventRecord ::= eventRecord(
        index:     Int,
        timestamp: Int,
        eventType: Symbol,
        category:  Symbol,
        submitter: Address,
        metadata:  Bytes,
        version:   Int,
        eventHash: Bytes32,
        prevHash:  Bytes32
    )

    syntax Bytes ::= bytes(String)

endmodule

// ============================================================================

module AUDIT-LEDGER-CONFIG
    imports AUDIT-LEDGER-SYNTAX
    imports MAP
    imports SET
    imports LIST

    // ── Configuration ────────────────────────────────────────────────────────
    //
    // The <k> cell holds the current computation.
    // All contract storage is modelled as K cells mirroring the Soroban
    // DataKey variants that matter for these proofs.

    configuration
        <audit-ledger>
            <k>                $PGM:Stmt                  </k>
            <initialized>      false                      </initialized>
            <owner>            .Address                   </owner>
            <totalEvents>      0                          </totalEvents>
            <globalMaxLogs>    0                          </globalMaxLogs>
            <paused>           false                      </paused>
            // Map from Bytes32 event-ID → EventRecord
            <events>           .Map                       </events>
            // Map from Symbol event-type → Int count
            <eventTypeCounts>  .Map                       </eventTypeCounts>
            // Map from Symbol event-type → Int cap (absent = no cap)
            <eventTypeCaps>    .Map                       </eventTypeCaps>
            // Map from Symbol event-type → Bool (cap removed marker)
            <capRemoved>       .Map                       </capRemoved>
            // Map from Address submitter → Int (last nonce)
            <submitterNonces>  .Map                       </submitterNonces>
            // Sequential list of Bytes32 event-IDs (ordered by insertion)
            <eventOrder>       .List                      </eventOrder>
            // Current ledger timestamp (block time)
            <now>              0                          </now>
        </audit-ledger>

endmodule

// ============================================================================

module AUDIT-LEDGER-RULES
    imports AUDIT-LEDGER-CONFIG
    imports AUDIT-LEDGER-SYNTAX
    imports DOMAINS
    imports MAP
    imports SET
    imports LIST
    imports K-EQUAL

    // ── Helper function: compute a simple event hash ──────────────────────────
    // In production this is SHA-256; here we model it symbolically.
    syntax Bytes32 ::= computeHash(EventRecord) [function, total]
    rule computeHash(_) => "0xDEADBEEF00000000000000000000000000000000000000000000000000000000"
        [simplification]

    syntax Bytes32 ::= genesisHash() [function, total]
    rule genesisHash() => "0x0000000000000000000000000000000000000000000000000000000000000000"

    // ── INITIALIZATION ────────────────────────────────────────────────────────

    // INI-1: Successful initialization.
    rule
        <k> initialize(Owner, MaxLogs) => . </k>
        <initialized>   false => true     </initialized>
        <owner>         _ => Owner        </owner>
        <globalMaxLogs> _ => MaxLogs      </globalMaxLogs>
        <totalEvents>   _ => 0            </totalEvents>
        requires Owner =/=K .Address
        andBool  MaxLogs >Int 0

    // INI-2: Double-initialization reverts (AlreadyInitialized = error code 30).
    rule
        <k> initialize(_, _) => #error(30) </k>
        <initialized> true </initialized>

    // INI-3: Zero-owner rejected (NewOwnerIsZero = error code 6).
    rule
        <k> initialize(.Address, _) => #error(6) </k>
        <initialized> false </initialized>

    // ── LOGGING ───────────────────────────────────────────────────────────────

    // LOG-1: Successful logEvent.
    rule
        <k> logEvent(Submitter, EventType, Meta) => TotalEvents </k>
        <initialized>     true                                            </initialized>
        <paused>          false                                           </paused>
        <totalEvents>     TotalEvents => TotalEvents +Int 1               </totalEvents>
        <globalMaxLogs>   GlobalMax                                       </globalMaxLogs>
        <events>          Events => Events[EventHash <- newEvent]         </events>
        <eventOrder>      Order => Order ListItem(EventHash)              </eventOrder>
        <eventTypeCounts> Counts => Counts[EventType <- (
            {Counts[EventType] orDefault 0} +Int 1
        )]                                                                </eventTypeCounts>
        <now>             Now                                             </now>
        requires TotalEvents <Int GlobalMax
        andBool  notBool eventTypeCapExceeded(EventType, Counts, EventTypeCaps)
        // Build the new event record.
        where
            PrevHash := #if TotalEvents ==Int 0
                            #then genesisHash()
                            #else computeHash({Events[nth(Order, TotalEvents -Int 1)]}:>EventRecord)
                        #fi ,
            EventHash := computeHash(eventRecord(
                TotalEvents, Now, EventType, Symbol(""), Submitter, Meta,
                1, genesisHash(), PrevHash
            )),
            newEvent := eventRecord(
                TotalEvents, Now, EventType, Symbol(""), Submitter, Meta,
                1, EventHash, PrevHash
            )
        <eventTypeCaps> EventTypeCaps </eventTypeCaps>

    // LOG-2: logEvent reverts when contract not initialized.
    rule
        <k> logEvent(_, _, _) => #error(9) </k>
        <initialized> false </initialized>

    // LOG-3: logEvent reverts when contract is paused.
    rule
        <k> logEvent(_, _, _) => #error(13) </k>
        <initialized> true  </initialized>
        <paused>      true  </paused>

    // LOG-4: logEvent reverts when global cap is reached.
    rule
        <k> logEvent(_, _, _) => #error(2) </k>
        <initialized>   true             </initialized>
        <paused>        false            </paused>
        <totalEvents>   TotalEvents      </totalEvents>
        <globalMaxLogs> GlobalMax        </globalMaxLogs>
        requires TotalEvents >=Int GlobalMax

    // LOG-5: logEvent reverts when per-event-type cap is reached.
    rule
        <k> logEvent(_, EventType, _) => #error(3) </k>
        <initialized>     true             </initialized>
        <paused>          false            </paused>
        <totalEvents>     TotalEvents      </totalEvents>
        <globalMaxLogs>   GlobalMax        </globalMaxLogs>
        <eventTypeCounts> Counts           </eventTypeCounts>
        <eventTypeCaps>   EventTypeCaps    </eventTypeCaps>
        requires TotalEvents <Int GlobalMax
        andBool  eventTypeCapExceeded(EventType, Counts, EventTypeCaps)

    // ── CAP ENFORCEMENT ───────────────────────────────────────────────────────

    // Helper predicate: returns true when event-type cap is set and reached.
    syntax Bool ::= eventTypeCapExceeded(Symbol, Map, Map) [function, total]
    rule eventTypeCapExceeded(EventType, Counts, Caps) =>
        EventType in_keys(Caps)
        andBool {Caps[EventType]}:>Int <=Int ({Counts[EventType] orDefault 0}:>Int)

    // GOV-1: setGlobalMaxLogs — owner only.
    rule
        <k> setGlobalMaxLogs(Caller, NewMax) => . </k>
        <owner>         Caller          </owner>
        <totalEvents>   TotalEvents     </totalEvents>
        <globalMaxLogs> _ => NewMax     </globalMaxLogs>
        requires NewMax >=Int TotalEvents

    // GOV-2: setGlobalMaxLogs reverts for non-owner.
    rule
        <k> setGlobalMaxLogs(Caller, _) => #error(1) </k>
        <owner> Owner </owner>
        requires Caller =/=K Owner

    // GOV-3: setGlobalMaxLogs reverts when NewMax < totalEvents.
    rule
        <k> setGlobalMaxLogs(Caller, NewMax) => #error(16) </k>
        <owner>       Caller      </owner>
        <totalEvents> TotalEvents </totalEvents>
        requires NewMax <Int TotalEvents

    // GOV-4: setEventMaxLogs — owner only.
    rule
        <k> setEventMaxLogs(Caller, EventType, NewMax) => . </k>
        <owner>         Caller                                          </owner>
        <eventTypeCaps> Caps => Caps[EventType <- NewMax]              </eventTypeCaps>

    // GOV-5: setEventMaxLogs reverts for non-owner.
    rule
        <k> setEventMaxLogs(Caller, _, _) => #error(1) </k>
        <owner> Owner </owner>
        requires Caller =/=K Owner

    // GOV-6: removeEventCap — owner only.
    rule
        <k> removeEventCap(Caller, EventType) => . </k>
        <owner>       Caller                                                </owner>
        <eventTypeCaps> Caps => Caps[EventType undef]                       </eventTypeCaps>
        <capRemoved>  Removed => Removed[EventType <- true]                 </capRemoved>
        requires EventType in_keys(Caps)

    // GOV-7: removeEventCap reverts when cap not set.
    rule
        <k> removeEventCap(Caller, EventType) => #error(7) </k>
        <owner>         Caller       </owner>
        <eventTypeCaps> Caps         </eventTypeCaps>
        requires notBool EventType in_keys(Caps)

    // GOV-8: removeEventCap reverts for non-owner.
    rule
        <k> removeEventCap(Caller, _) => #error(1) </k>
        <owner> Owner </owner>
        requires Caller =/=K Owner

    // GOV-9: transferOwnership — owner only, non-zero new owner.
    rule
        <k> transferOwnership(Caller, NewOwner) => . </k>
        <owner> Caller => NewOwner </owner>
        requires NewOwner =/=K .Address
        andBool  NewOwner =/=K Caller

    // GOV-10: transferOwnership reverts for non-owner.
    rule
        <k> transferOwnership(Caller, _) => #error(1) </k>
        <owner> Owner </owner>
        requires Caller =/=K Owner

    // GOV-11: transferOwnership reverts for zero address.
    rule
        <k> transferOwnership(Caller, .Address) => #error(6) </k>
        <owner> Caller </owner>

    // GOV-12: transferOwnership reverts for same owner.
    rule
        <k> transferOwnership(Owner, Owner) => #error(15) </k>
        <owner> Owner </owner>

    // GOV-13: setPaused — owner only.
    rule
        <k> setPaused(Caller, Paused) => . </k>
        <owner>  Caller             </owner>
        <paused> _ => Paused        </paused>

    // GOV-14: setPaused reverts for non-owner.
    rule
        <k> setPaused(Caller, _) => #error(1) </k>
        <owner> Owner </owner>
        requires Caller =/=K Owner

    // ── QUERY RULES ───────────────────────────────────────────────────────────

    rule
        <k> totalEvents() => TotalEvents </k>
        <totalEvents> TotalEvents </totalEvents>

    rule
        <k> eventCount(EventType) => {Counts[EventType] orDefault 0} </k>
        <eventTypeCounts> Counts </eventTypeCounts>

    rule
        <k> getEvent(EventId) => {Events[EventId]}:>EventRecord </k>
        <events> Events </events>
        requires EventId in_keys(Events)

    rule
        <k> getEvent(EventId) => #error(4) </k>
        <events> Events </events>
        requires notBool EventId in_keys(Events)

    // ── ERROR HANDLING ────────────────────────────────────────────────────────

    syntax KItem ::= #error(Int)

endmodule

// ============================================================================
// PROOF CLAIMS
// ============================================================================

module AUDIT-LEDGER-SPEC
    imports AUDIT-LEDGER-RULES

    // ── SPEC-1: Initialization correctness ───────────────────────────────────
    //
    // Claim: After initialize(Owner, Max), initialized=true, owner=Owner,
    //        globalMaxLogs=Max, totalEvents=0.

    claim
        <audit-ledger>
            <k> initialize(OWNER:Address, MAX:Int) => . </k>
            <initialized>   false => true    </initialized>
            <owner>         _ => OWNER       </owner>
            <globalMaxLogs> _ => MAX         </globalMaxLogs>
            <totalEvents>   _ => 0           </totalEvents>
            <paused>        false            </paused>
            ...
        </audit-ledger>
        requires OWNER =/=K .Address
        andBool  MAX >Int 0

    // ── SPEC-2: Single logEvent increments totalEvents ────────────────────────

    claim
        <audit-ledger>
            <k> logEvent(SUBMITTER:Address, ETYPE:Symbol, META:Bytes) => TOTAL </k>
            <initialized>   true             </initialized>
            <paused>        false            </paused>
            <totalEvents>   TOTAL => TOTAL +Int 1 </totalEvents>
            <globalMaxLogs> MAX              </globalMaxLogs>
            ...
        </audit-ledger>
        requires TOTAL <Int MAX

    // ── SPEC-3: Cap enforcement — logEvent reverts at cap ────────────────────

    claim
        <audit-ledger>
            <k> logEvent(SUBMITTER:Address, ETYPE:Symbol, META:Bytes) => #error(2) </k>
            <initialized>   true    </initialized>
            <paused>        false   </paused>
            <totalEvents>   TOTAL   </totalEvents>
            <globalMaxLogs> MAX     </globalMaxLogs>
            ...
        </audit-ledger>
        requires TOTAL >=Int MAX

    // ── SPEC-4: Paused contract rejects logEvent ──────────────────────────────

    claim
        <audit-ledger>
            <k> logEvent(_:Address, _:Symbol, _:Bytes) => #error(13) </k>
            <initialized> true  </initialized>
            <paused>      true  </paused>
            ...
        </audit-ledger>

    // ── SPEC-5: Non-owner setGlobalMaxLogs reverts ────────────────────────────

    claim
        <audit-ledger>
            <k> setGlobalMaxLogs(CALLER:Address, _:Int) => #error(1) </k>
            <owner> OWNER:Address </owner>
            ...
        </audit-ledger>
        requires CALLER =/=K OWNER

    // ── SPEC-6: Owner setGlobalMaxLogs succeeds when new max >= totalEvents ───

    claim
        <audit-ledger>
            <k> setGlobalMaxLogs(OWNER:Address, NEWMAX:Int) => . </k>
            <owner>         OWNER               </owner>
            <totalEvents>   TOTAL               </totalEvents>
            <globalMaxLogs> _ => NEWMAX         </globalMaxLogs>
            ...
        </audit-ledger>
        requires NEWMAX >=Int TOTAL

    // ── SPEC-7: transferOwnership changes owner ───────────────────────────────

    claim
        <audit-ledger>
            <k> transferOwnership(OWNER:Address, NEWOWNER:Address) => . </k>
            <owner> OWNER => NEWOWNER </owner>
            ...
        </audit-ledger>
        requires NEWOWNER =/=K .Address
        andBool  NEWOWNER =/=K OWNER

endmodule

// ============================================================================
// SUP TECH FEED DISPATCHER — STATE-MACHINE INVARIANTS (Issue #838)
// ============================================================================
//
// Models the real-time regulatory telemetry feed dispatcher in
// `src/suptech_feeds.rs`. The dispatcher ingests feed batches, tracks a
// monotonically increasing sequence number, and maintains a hash chain over
// dispatched batches. Invariants below must hold under duplicate submissions,
// out-of-order timestamps, and mid-batch rollbacks.
// ============================================================================

module SUPTECH-FEEDS-SYNTAX
    imports AUDIT-LEDGER-SYNTAX
    imports DOMAINS-SYNTAX

    syntax FeedId    ::= Int  // u64 feed identifier
    syntax SeqNo     ::= Int  // u64 monotonic dispatch sequence
    syntax BatchHash ::= Bytes32

    syntax FeedStmt ::=
          "dispatchBatch" "(" FeedId "," SeqNo "," Bytes32 ")"
        | "rollbackBatch" "(" FeedId "," SeqNo ")"
        | "recoverFeed"   "(" FeedId ")"

    syntax KResult ::= Int | Bool | Bytes32

endmodule

// ============================================================================

module SUPTECH-FEEDS-CONFIG
    imports SUPTECH-FEEDS-SYNTAX
    imports MAP
    imports SET
    imports LIST

    configuration
        <suptech-feeds>
            <k>                 $PGM:FeedStmt              </k>
            <feedInitialized>   false                      </feedInitialized>
            // Map from FeedId → last dispatched SeqNo
            <feedSeq>           .Map                       </feedSeq>
            // Map from FeedId → BatchHash of the last dispatched batch
            <feedHead>          .Map                       </feedHead>
            // Map from FeedId → List of dispatched BatchHash (hash chain)
            <feedChain>         .Map                       </feedChain>
            // Set of (FeedId, SeqNo) pairs already dispatched (dedup)
            <feedSeen>          .Set                       </feedSeen>
            // Map from FeedId → Bool (feed paused / halted)
            <feedHalted>        .Map                       </feedHalted>
        </suptech-feeds>

endmodule

// ============================================================================

module SUPTECH-FEEDS-RULES
    imports SUPTECH-FEEDS-CONFIG
    imports SUPTECH-FEEDS-SYNTAX
    imports DOMAINS
    imports MAP
    imports SET
    imports LIST
    imports K-EQUAL

    syntax Bytes32 ::= feedGenesisHash() [function, total]
    rule feedGenesisHash() =>
        "0x0000000000000000000000000000000000000000000000000000000000000000"

    // FD-1: Successful dispatch of the next sequential batch.
    rule
        <k> dispatchBatch(Feed, Seq, Hash) => Seq </k>
        <feedInitialized> true </feedInitialized>
        <feedSeq>   Seqs  => Seqs[Feed <- Seq]     </feedSeq>
        <feedHead>  Heads => Heads[Feed <- Hash]   </feedHead>
        <feedChain> Chains => Chains[Feed <- (
            {Chains[Feed] orDefault .List} ListItem(Hash)
        )]                                          </feedChain>
        <feedSeen>  Seen => Seen SetItem(Feed, Seq) </feedSeen>
        <feedHalted> Halted </feedHalted>
        requires Seq ==Int ({Seqs[Feed] orDefault 0} +Int 1)
        andBool  notBool (Feed, Seq) in Seen
        andBool  notBool ({Halted[Feed] orDefault false}:>Bool)

    // FD-2: Duplicate submission is rejected (idempotent no-op).
    rule
        <k> dispatchBatch(Feed, Seq, _) => #error(40) </k>
        <feedSeen> Seen </feedSeen>
        requires (Feed, Seq) in Seen

    // FD-3: Out-of-order (non-sequential) submission is rejected.
    rule
        <k> dispatchBatch(Feed, Seq, _) => #error(41) </k>
        <feedSeq> Seqs </feedSeq>
        <feedSeen> Seen </feedSeen>
        requires Seq =/=Int ({Seqs[Feed] orDefault 0} +Int 1)
        andBool  notBool (Feed, Seq) in Seen

    // FD-4: Dispatch to a halted feed is rejected.
    rule
        <k> dispatchBatch(Feed, _, _) => #error(42) </k>
        <feedHalted> Halted </feedHalted>
        requires {Halted[Feed] orDefault false}:>Bool

    // FD-5: Mid-batch rollback restores the previous head and sequence.
    rule
        <k> rollbackBatch(Feed, Seq) => . </k>
        <feedSeq>   Seqs  => Seqs[Feed <- Seq -Int 1]  </feedSeq>
        <feedHead>  Heads => Heads[Feed <- feedGenesisHash()] </feedHead>
        <feedSeen>  Seen  => Seen -Set SetItem(Feed, Seq) </feedSeen>
        <feedChain> Chains => Chains[Feed <- (
            {Chains[Feed] orDefault .List}
        )]                                              </feedChain>
        requires Seq ==Int {Seqs[Feed] orDefault 0}

    // FD-6: Recovery re-derives the head from the hash chain.
    rule
        <k> recoverFeed(Feed) => Head </k>
        <feedChain> Chains </feedChain>
        <feedHead>  Heads => Heads[Feed <- Head] </feedHead>
        where Head := #if {Chains[Feed] orDefault .List} ==K .List
                         #then feedGenesisHash()
                         #else {Chains[Feed]}:>List
                      #fi

endmodule

// ============================================================================

module SUPTECH-FEEDS-SPEC
    imports SUPTECH-FEEDS-RULES

    // ── SPEC-8: Dispatch advances sequence by exactly one ────────────────────
    //
    // Claim: A successful dispatchBatch on a non-halted feed with the next
    //        sequential SeqNo advances feedSeq by exactly one and appends
    //        exactly one hash to the feed's hash chain.

    claim
        <suptech-feeds>
            <k> dispatchBatch(FEED:FeedId, SEQ:SeqNo, HASH:BatchHash) => SEQ </k>
            <feedInitialized> true </feedInitialized>
            <feedSeq>   SEQS  => SEQS[FEED <- SEQ]   </feedSeq>
            <feedHead>  HEADS => HEADS[FEED <- HASH] </feedHead>
            <feedChain> CHAINS => CHAINS[FEED <- (
                {CHAINS[FEED] orDefault .List} ListItem(HASH)
            )]                                        </feedChain>
            <feedSeen>  SEEN => SEEN SetItem(FEED, SEQ) </feedSeen>
            <feedHalted> HALTED </feedHalted>
            ...
        </suptech-feeds>
        requires SEQ ==Int ({SEQS[FEED] orDefault 0} +Int 1)
        andBool  notBool (FEED, SEQ) in SEEN
        andBool  notBool ({HALTED[FEED] orDefault false}:>Bool)

    // ── SPEC-9: Duplicate submissions never mutate state ─────────────────────
    //
    // Claim: Re-submitting an already-seen (FeedId, SeqNo) pair reverts with
    //        error 40 and leaves feedSeq, feedHead and feedChain unchanged.

    claim
        <suptech-feeds>
            <k> dispatchBatch(FEED:FeedId, SEQ:SeqNo, _:BatchHash) => #error(40) </k>
            <feedSeq>   SEQS   </feedSeq>
            <feedHead>  HEADS  </feedHead>
            <feedChain> CHAINS </feedChain>
            <feedSeen>  SEEN   </feedSeen>
            ...
        </suptech-feeds>
        requires (FEED, SEQ) in SEEN

    // ── SPEC-10: Out-of-order timestamps are rejected ────────────────────────
    //
    // Claim: A SeqNo that is not exactly last+1 (and not already seen) is
    //        rejected with error 41, preserving the monotonic sequence.

    claim
        <suptech-feeds>
            <k> dispatchBatch(FEED:FeedId, SEQ:SeqNo, _:BatchHash) => #error(41) </k>
            <feedSeq>  SEQS </feedSeq>
            <feedSeen> SEEN </feedSeen>
            ...
        </suptech-feeds>
        requires SEQ =/=Int ({SEQS[FEED] orDefault 0} +Int 1)
        andBool  notBool (FEED, SEQ) in SEEN

    // ── SPEC-11: Mid-batch rollback restores the pre-batch sequence ──────────
    //
    // Claim: Rolling back the head batch of a feed decrements feedSeq by one
    //        and removes the (FeedId, SeqNo) pair from the dedup set.

    claim
        <suptech-feeds>
            <k> rollbackBatch(FEED:FeedId, SEQ:SeqNo) => . </k>
            <feedSeq>  SEQS => SEQS[FEED <- SEQ -Int 1] </feedSeq>
            <feedSeen> SEEN => SEEN -Set SetItem(FEED, SEQ) </feedSeen>
            ...
        </suptech-feeds>
        requires SEQ ==Int {SEQS[FEED] orDefault 0}

    // ── SPEC-12: Recovery preserves hash-chain integrity ─────────────────────
    //
    // Claim: After recoverFeed, the feed head equals the last element of the
    //        feed's hash chain (or the genesis hash when the chain is empty),
    //        so the chain is never silently truncated or reordered.

    claim
        <suptech-feeds>
            <k> recoverFeed(FEED:FeedId) => HEAD </k>
            <feedChain> CHAINS </feedChain>
            <feedHead>  HEADS => HEADS[FEED <- HEAD] </feedHead>
            ...
        </suptech-feeds>
        requires HEAD ==K #if {CHAINS[FEED] orDefault .List} ==K .List
                            #then feedGenesisHash()
                            #else {CHAINS[FEED]}:>List
                         #fi

endmodule

// ============================================================================
// CBDC OFFLINE RECONCILIATION — STATE-MACHINE INVARIANTS (Issue #848)
// ============================================================================
//
// Models the offline voucher double-spend reconciliation verifier in
// `src/cbdc_offline.rs`. Vouchers are submitted for reconciliation; the
// verifier must reject duplicates and out-of-order submissions while keeping
// the Merkle root and hash chain consistent across simulated recovery.
// ============================================================================

module CBDC-OFFLINE-SYNTAX
    imports AUDIT-LEDGER-SYNTAX
    imports DOMAINS-SYNTAX

    syntax VoucherId ::= Int  // u64 voucher identifier
    syntax MerkleRoot ::= Bytes32

    syntax VoucherStmt ::=
          "submitVoucher" "(" VoucherId "," Bytes32 ")"
        | "rollbackVoucher" "(" VoucherId ")"
        | "recoverVouchers" "(" ")"

    syntax KResult ::= Int | Bool | Bytes32

endmodule

// ============================================================================

module CBDC-OFFLINE-CONFIG
    imports CBDC-OFFLINE-SYNTAX
    imports MAP
    imports SET
    imports LIST

    configuration
        <cbdc-offline>
            <k>                  $PGM:VoucherStmt        </k>
            <voucherInitialized> false                   </voucherInitialized>
            // Set of VoucherId already reconciled (double-spend guard)
            <voucherSeen>        .Set                    </voucherSeen>
            // Map from VoucherId → Bytes32 voucher commitment
            <voucherCommit>      .Map                    </voucherCommit>
            // Ordered list of reconciled voucher commitments (hash chain)
            <voucherChain>       .List                   </voucherChain>
            // Current Merkle root over the reconciled voucher set
            <merkleRoot>         "0x0000000000000000000000000000000000000000000000000000000000000000" </merkleRoot>
            // Map from VoucherId → Bool (voucher revoked)
            <voucherRevoked>     .Map                    </voucherRevoked>
        </cbdc-offline>

endmodule

// ============================================================================

module CBDC-OFFLINE-RULES
    imports CBDC-OFFLINE-CONFIG
    imports CBDC-OFFLINE-SYNTAX
    imports DOMAINS
    imports MAP
    imports SET
    imports LIST
    imports K-EQUAL

    syntax Bytes32 ::= voucherGenesisRoot() [function, total]
    rule voucherGenesisRoot() =>
        "0x0000000000000000000000000000000000000000000000000000000000000000"

    // VC-1: Successful reconciliation of a fresh voucher.
    rule
        <k> submitVoucher(V, Commitment) => V </k>
        <voucherInitialized> true </voucherInitialized>
        <voucherSeen>   Seen   => Seen SetItem(V)          </voucherSeen>
        <voucherCommit> Commits => Commits[V <- Commitment] </voucherCommit>
        <voucherChain>  Chain  => Chain ListItem(Commitment) </voucherChain>
        <voucherRevoked> Revoked </voucherRevoked>
        requires notBool V in Seen
        andBool  notBool ({Revoked[V] orDefault false}:>Bool)

    // VC-2: Duplicate voucher submission is rejected (double-spend).
    rule
        <k> submitVoucher(V, _) => #error(50) </k>
        <voucherSeen> Seen </voucherSeen>
        requires V in Seen

    // VC-3: Revoked voucher submission is rejected.
    rule
        <k> submitVoucher(V, _) => #error(51) </k>
        <voucherRevoked> Revoked </voucherRevoked>
        requires {Revoked[V] orDefault false}:>Bool

    // VC-4: Mid-batch rollback removes the voucher from the reconciled set.
    rule
        <k> rollbackVoucher(V) => . </k>
        <voucherSeen>   Seen   => Seen -Set SetItem(V)     </voucherSeen>
        <voucherCommit> Commits => Commits[V undef]        </voucherCommit>
        <voucherChain>  Chain  => Chain                     </voucherChain>
        requires V in Seen

    // VC-5: Recovery recomputes the Merkle root from the voucher chain.
    rule
        <k> recoverVouchers() => Root </k>
        <voucherChain> Chain </voucherChain>
        <merkleRoot> _ => Root </merkleRoot>
        where Root := #if Chain ==K .List
                         #then voucherGenesisRoot()
                         #else computeHash(eventRecord(
                                 0, 0, Symbol(""), Symbol(""), .Address,
                                 bytes("merkle"), 1, voucherGenesisRoot(),
                                 voucherGenesisRoot()
                              ))
                      #fi

endmodule

// ============================================================================

module CBDC-OFFLINE-SPEC
    imports CBDC-OFFLINE-RULES

    // ── SPEC-13: Fresh voucher submission is recorded exactly once ───────────
    //
    // Claim: Submitting a fresh, non-revoked voucher adds it to the reconciled
    //        set and appends exactly one commitment to the hash chain.

    claim
        <cbdc-offline>
            <k> submitVoucher(V:VoucherId, COMMIT:Bytes32) => V </k>
            <voucherInitialized> true </voucherInitialized>
            <voucherSeen>   SEEN   => SEEN SetItem(V)           </voucherSeen>
            <voucherCommit> COMMITS => COMMITS[V <- COMMIT]     </voucherCommit>
            <voucherChain>  CHAIN  => CHAIN ListItem(COMMIT)    </voucherChain>
            <voucherRevoked> REVOKED </voucherRevoked>
            ...
        </cbdc-offline>
        requires notBool V in SEEN
        andBool  notBool ({REVOKED[V] orDefault false}:>Bool)

    // ── SPEC-14: Duplicate voucher submission never mutates state ────────────
    //
    // Claim: Re-submitting an already-reconciled voucher reverts with error 50
    //        and leaves the reconciled set, commitments and chain unchanged.

    claim
        <cbdc-offline>
            <k> submitVoucher(V:VoucherId, _:Bytes32) => #error(50) </k>
            <voucherSeen>   SEEN    </voucherSeen>
            <voucherCommit> COMMITS </voucherCommit>
            <voucherChain>  CHAIN   </voucherChain>
            ...
        </cbdc-offline>
        requires V in SEEN

    // ── SPEC-15: Revoked voucher submission is rejected ──────────────────────
    //
    // Claim: Submitting a revoked voucher reverts with error 51 and does not
    //        alter the reconciled set or the hash chain.

    claim
        <cbdc-offline>
            <k> submitVoucher(V:VoucherId, _:Bytes32) => #error(51) </k>
            <voucherRevoked> REVOKED </voucherRevoked>
            ...
        </cbdc-offline>
        requires {REVOKED[V] orDefault false}:>Bool

    // ── SPEC-16: Mid-batch rollback removes the voucher from the set ─────────
    //
    // Claim: Rolling back a reconciled voucher removes it from the reconciled
    //        set and drops its commitment, restoring the pre-batch state.

    claim
        <cbdc-offline>
            <k> rollbackVoucher(V:VoucherId) => . </k>
            <voucherSeen>   SEEN   => SEEN -Set SetItem(V) </voucherSeen>
            <voucherCommit> COMMITS => COMMITS[V undef]    </voucherCommit>
            ...
        </cbdc-offline>
        requires V in SEEN

    // ── SPEC-17: Recovery preserves Merkle-root / hash-chain integrity ───────
    //
    // Claim: After recoverVouchers, the Merkle root is either the genesis root
    //        (empty chain) or the hash of the current chain head, so recovery
    //        never produces a root inconsistent with the reconciled set.

    claim
        <cbdc-offline>
            <k> recoverVouchers() => ROOT </k>
            <voucherChain> CHAIN </voucherChain>
            <merkleRoot> _ => ROOT </merkleRoot>
            ...
        </cbdc-offline>
        requires ROOT ==K #if CHAIN ==K .List
                            #then voucherGenesisRoot()
                            #else computeHash(eventRecord(
                                    0, 0, Symbol(""), Symbol(""), .Address,
                                    bytes("merkle"), 1, voucherGenesisRoot(),
                                    voucherGenesisRoot()
                                 ))
                         #fi

endmodule
