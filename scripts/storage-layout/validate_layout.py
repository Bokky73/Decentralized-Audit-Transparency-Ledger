#!/usr/bin/env python3
"""
validate_layout.py — Compare two storage layout snapshots and report violations.

Usage:
    python3 validate_layout.py --old snapshots/baseline.json \
                               --new snapshots/current.json \
                               [--strict] \
                               [--allow-tombstone-removal]

Exit codes:
    0 — compatible (or only warnings without --strict)
    1 — warnings with --strict flag
    2 — breaking violations
"""

from __future__ import annotations

import argparse
import sys
import os
from pathlib import Path

# Allow importing layout_utils from the same directory
sys.path.insert(0, str(Path(__file__).parent))
from layout_utils import load_snapshot, validate_snapshots


# ---------------------------------------------------------------------------
# Storage footprint budgets (serialized XDR byte sizes)
# ---------------------------------------------------------------------------
#
# These budgets pin the serialized XDR byte footprint of records managed by
# `src/supply_chain.rs`. They are checked against the candidate snapshot and
# the build fails when a record grows beyond its budget. Update the budgets
# deliberately (and re-pin the snapshot tests) whenever the layout changes.
#
# Structure: { "supply_chain": { "<record>": <max_bytes> } }

STORAGE_FOOTPRINT_BUDGETS: dict[str, dict[str, int]] = {
    "supply_chain": {
        # Composite custody-handoff records (packed fields + enum discriminants)
        "CustodyHandoff": 128,
        "SupplyChainRecord": 192,
        "HandoffVerification": 96,
        # TTL / archival bookkeeping
        "TtlPolicy": 48,
        "ArchivalRecord": 64,
    },
}


def check_storage_footprint(
    new_snapshot: dict,
    budgets: dict[str, dict[str, int]] | None = None,
) -> list:
    """Return a list of footprint violations for the candidate snapshot.

    Each violation is a dict with keys: ``module``, ``record``, ``actual``,
    ``budget``. A record is flagged when its serialized XDR byte size exceeds
    the pinned budget. Missing records are ignored (they may be added later),
    but records present in the snapshot without a budget are reported as
    violations so new state keys cannot silently escape the byte budget.
    """
    if budgets is None:
        budgets = STORAGE_FOOTPRINT_BUDGETS

    violations: list = []
    modules = new_snapshot.get("modules", {})

    for module, record_budgets in budgets.items():
        module_data = modules.get(module)
        if not module_data:
            continue

        records = module_data.get("records", {})
        for record_name, record in records.items():
            actual = record.get("xdr_size", record.get("size"))
            if actual is None:
                continue

            budget = record_budgets.get(record_name)
            if budget is None:
                violations.append(
                    {
                        "module": module,
                        "record": record_name,
                        "actual": actual,
                        "budget": None,
                    }
                )
                continue

            if actual > budget:
                violations.append(
                    {
                        "module": module,
                        "record": record_name,
                        "actual": actual,
                        "budget": budget,
                    }
                )

    return violations


def print_footprint_report(violations: list) -> None:
    if not violations:
        print(_green(_bold("✓ Storage footprint within budget.")))
        print()
        return

    print(_bold(_red(f"STORAGE FOOTPRINT VIOLATIONS ({len(violations)}):")))
    for v in violations:
        if v["budget"] is None:
            print(
                f"  {_red('✗')} [{v['module']}] '{v['record']}' "
                f"xdr_size={v['actual']} has no pinned byte budget"
            )
        else:
            over = v["actual"] - v["budget"]
            print(
                f"  {_red('✗')} [{v['module']}] '{v['record']}' "
                f"xdr_size={v['actual']} exceeds budget={v['budget']} (+{over} bytes)"
            )
    print()


# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

def _use_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR", "") == ""


def _green(s: str) -> str:
    return f"\033[32m{s}\033[0m" if _use_color() else s


def _yellow(s: str) -> str:
    return f"\033[33m{s}\033[0m" if _use_color() else s


def _red(s: str) -> str:
    return f"\033[31m{s}\033[0m" if _use_color() else s


def _bold(s: str) -> str:
    return f"\033[1m{s}\033[0m" if _use_color() else s


# ---------------------------------------------------------------------------
# Report printer
# ---------------------------------------------------------------------------

def print_report(
    old_snapshot: dict,
    new_snapshot: dict,
    violations: list,
    warnings: list,
    strict: bool,
) -> None:
    old_contract = old_snapshot.get("contract", "?")
    new_commit = new_snapshot.get("git_commit", "?")
    old_commit = old_snapshot.get("git_commit", "?")

    print()
    print(_bold("═══════════════════════════════════════════════════"))
    print(_bold("  Storage Layout Compatibility Report"))
    print(_bold("═══════════════════════════════════════════════════"))
    print(f"  Contract : {old_contract}")
    print(f"  Baseline : {old_commit}")
    print(f"  Candidate: {new_commit}")
    print()

    # PASSED checks
    checks = [
        "No ordinal reuse",
        "No type changes",
        "Append-only additions",
        "Variant order preserved",
        "No non-tombstone removals",
    ]
    violation_rules = {v.rule for v in violations}

    rule_to_check = {
        "no_ordinal_reuse": "No ordinal reuse",
        "no_type_change": "No type changes",
        "append_only": "Append-only additions",
        "order_preserved": "Variant order preserved",
        "no_removal": "No non-tombstone removals",
    }

    failed_checks = {rule_to_check.get(r, r) for r in violation_rules}
    warning_rules = {w.rule for w in warnings}
    warned_checks = {rule_to_check.get(r, r) for r in warning_rules}

    print(_bold("CHECKS:"))
    for check in checks:
        if check in failed_checks:
            print(f"  {_red('✗')} {check}")
        elif check in warned_checks:
            print(f"  {_yellow('⚠')} {check}")
        else:
            print(f"  {_green('✓')} {check}")
    print()

    # VIOLATIONS
    if violations:
        print(_bold(_red(f"VIOLATIONS ({len(violations)}):")))
        for v in violations:
            ordinal_str = f"ordinal={v.ordinal}" if v.ordinal >= 0 else ""
            print(f"  {_red('✗')} [{v.rule}] '{v.variant_name}' {ordinal_str}")
            # Wrap description
            desc = v.description
            words = desc.split()
            line = "      "
            for word in words:
                if len(line) + len(word) + 1 > 78:
                    print(line)
                    line = "      " + word + " "
                else:
                    line += word + " "
            if line.strip():
                print(line)
        print()

    # WARNINGS
    if warnings:
        print(_bold(_yellow(f"WARNINGS ({len(warnings)}):")))
        for w in warnings:
            print(f"  {_yellow('⚠')} [{w.rule}] '{w.variant_name}' ordinal={w.ordinal}")
            desc = w.description
            words = desc.split()
            line = "      "
            for word in words:
                if len(line) + len(word) + 1 > 78:
                    print(line)
                    line = "      " + word + " "
                else:
                    line += word + " "
            if line.strip():
                print(line)
        print()

    # Summary line
    if not violations and not warnings:
        print(_green(_bold("✓ Storage layout is compatible.")))
    elif not violations and warnings:
        if strict:
            print(_yellow(_bold(f"⚠ Storage layout has {len(warnings)} warning(s). --strict mode: treating as failure.")))
        else:
            print(_yellow(_bold(f"⚠ Storage layout has {len(warnings)} warning(s) but no breaking violations.")))
    else:
        print(_red(_bold(f"✗ Storage layout has {len(violations)} BREAKING violation(s).")))
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare two storage layout snapshots and report compatibility."
    )
    parser.add_argument(
        "--old",
        required=True,
        help="Path to the baseline (old) snapshot JSON.",
    )
    parser.add_argument(
        "--new",
        required=True,
        help="Path to the candidate (new) snapshot JSON.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        default=False,
        help="Treat warnings as failures (exit 1 on warnings).",
    )
    parser.add_argument(
        "--allow-tombstone-removal",
        action="store_true",
        default=False,
        help="Suppress warnings when tombstone variants are removed.",
    )
    args = parser.parse_args()

    try:
        old_snapshot = load_snapshot(args.old)
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"ERROR: Could not load old snapshot: {e}", file=sys.stderr)
        return 2

    try:
        new_snapshot = load_snapshot(args.new)
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"ERROR: Could not load new snapshot: {e}", file=sys.stderr)
        return 2

    violations, warnings = validate_snapshots(
        old_snapshot,
        new_snapshot,
        allow_tombstone_removal=args.allow_tombstone_removal,
    )

    print_report(old_snapshot, new_snapshot, violations, warnings, strict=args.strict)

    footprint_violations = check_storage_footprint(new_snapshot)
    print_footprint_report(footprint_violations)

    if violations or footprint_violations:
        return 2
    if warnings and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
