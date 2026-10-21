------------------------ MODULE SuptechStateMachine ------------------------
EXTENDS Naturals, Sequences, FiniteSets

VARIABLES
    evalLog,            \* Sequence of committed evaluation records
    seenIds,            \* Set of committed submission_ids
    lastTimestamp,      \* Maximum accepted event_timestamp
    maxDrift,           \* Configured out-of-order timestamp drift tolerance
    activeRules         \* Set of active rule_ids

vars == <<evalLog, seenIds, lastTimestamp, maxDrift, activeRules>>

Init ==
    /\ evalLog = <<>>
    /\ seenIds = {}
    /\ lastTimestamp = 0
    /\ maxDrift = 50
    /\ activeRules = {1, 2}

InvContiguousSequence ==
    \A i \in 1..Len(evalLog) : evalLog[i].seq = i - 1

InvNoDuplicateSubmissions ==
    /\ Cardinality(seenIds) = Len(evalLog)
    /\ \A i, j \in 1..Len(evalLog) :
        i # j => evalLog[i].id # evalLog[j].id

InvHashChainIntegrity ==
    \A i \in 2..Len(evalLog) :
        evalLog[i].prevHash = evalLog[i - 1].evalHash

StateInvariant ==
    /\ InvContiguousSequence
    /\ InvNoDuplicateSubmissions
    /\ InvHashChainIntegrity
=============================================================================
