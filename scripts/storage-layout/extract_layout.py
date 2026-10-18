#!/usr/bin/env python3
"""
extract_layout.py — Extracts the DataKey enum from a Rust source file
and emits a JSON snapshot for storage layout validation.

Usage:
    python3 extract_layout.py [--source src/lib.rs] \
                              [--output scripts/storage-layout/snapshots/current.json] \
                              [--contract AuditLedger]
"""

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
from pathlib import Path


TOMBSTONE_KEYWORDS = ("tombstone", "replaced by", "deprecated")

# Storage tier classification keywords. A variant's doc comment may declare its
# retention SLA tier explicitly (e.g. "Tier: Temporary"). When absent we fall
# back to a heuristic based on the variant name.
TIER_PERSISTENT = "Persistent"
TIER_TEMPORARY = "Temporary"
TIER_INSTANCE = "Instance"

TIER_KEYWORDS = {
    TIER_PERSISTENT: (
        "persistent",
        "permanent",
        "audit",
        "archive",
        "archival",
        "long-lived",
        "settlement",
        "iso20022",
        "iso-20022",
    ),
    TIER_TEMPORARY: (
        "temporary",
        "temp",
        "ephemeral",
        "transient",
        "short-lived",
        "nonce",
        "cache",
    ),
    TIER_INSTANCE: (
        "instance",
        "singleton",
        "config",
        "admin",
        "global",
        "governance",
        "rbac",
    ),
}

# Heuristic name-based tier classification used when no explicit tier is
# declared in the variant's doc comment.
INSTANCE_NAME_HINTS = ("admin", "config", "owner", "initialized", "paused", "version", "governance", "rbac")
TEMPORARY_NAME_HINTS = ("nonce", "cache", "temp", "pending", "session", "proof")

# Approximate XDR byte cost per primitive type.
PRIMITIVE_XDR_SIZES = {
    "u8": 4,
    "i8": 4,
    "u16": 4,
    "i16": 4,
    "u32": 4,
    "i32": 4,
    "u64": 8,
    "i64": 8,
    "u128": 16,
    "i128": 16,
    "u256": 32,
    "i256": 32,
    "bool": 4,
    "()": 0,
    "Address": 32,
    "Bytes": 4,
    "BytesN": 32,
    "Symbol": 4,
    "String": 4,
    "Vec": 4,
    "Map": 4,
}
XDR_TYPE_SIZES = PRIMITIVE_XDR_SIZES

# Fixed XDR overhead: enum discriminant (4 bytes) plus a small per-record
# envelope allowance for length prefixes / padding.
XDR_ENUM_DISCRIMINANT_SIZE = 4
XDR_RECORD_OVERHEAD = 4
# Bytes charged for a variable-length field (String, Bytes, Vec, Address, ...).
XDR_VARIABLE_FIELD_SIZE = 16
ENUM_DISCRIMINANT_BYTES = 4


def classify_tier(name_or_comment: str, comment_or_name: str = "") -> str:
    """Classify a variant into a storage tier based on comment then name."""
    haystack = f"{name_or_comment} {comment_or_name}".lower()
    for tier, keywords in TIER_KEYWORDS.items():
        if any(kw in haystack for kw in keywords):
            return tier

    if any(hint in haystack for hint in INSTANCE_NAME_HINTS):
        return TIER_INSTANCE
    if any(hint in haystack for hint in TEMPORARY_NAME_HINTS):
        return TIER_TEMPORARY
    return TIER_PERSISTENT


def estimate_field_size(field_type: str) -> int:
    """Estimate the XDR-encoded byte size of a single field type."""
    t = field_type.strip()
    t = re.sub(r"^&\s*(?:'[a-zA-Z_][a-zA-Z0-9_]*\s*)?", "", t)
    t = t.strip()

    if t in PRIMITIVE_XDR_SIZES:
        return PRIMITIVE_XDR_SIZES[t]

    if t.startswith("Option<") or t.startswith("Vec<") or t.startswith("("):
        return XDR_VARIABLE_FIELD_SIZE
    if t.startswith("String") or t.startswith("Bytes") or t.startswith("Symbol"):
        return XDR_VARIABLE_FIELD_SIZE
    if t.startswith("Address") or t.startswith("BytesN"):
        return XDR_VARIABLE_FIELD_SIZE

    return XDR_VARIABLE_FIELD_SIZE


def estimate_variant_size(variant: dict) -> int:
    """Estimate the serialized XDR byte size of a variant record."""
    size = XDR_ENUM_DISCRIMINANT_SIZE + XDR_RECORD_OVERHEAD
    for field in variant.get("fields", []):
        size += estimate_field_size(field.get("type") or "")
    return size


def estimate_xdr_size(fields: list) -> int:
    """Estimate the packed XDR serialized byte size of a variant's payload."""
    total = ENUM_DISCRIMINANT_BYTES
    for field in fields:
        ftype = (field.get("type") or "").strip()
        base = re.split(r"[<(\[]", ftype, maxsplit=1)[0].strip()
        base = base.lstrip("&").strip()
        total += XDR_TYPE_SIZES.get(base, 4)
    return total


def get_git_commit() -> str:
    """Return the current HEAD SHA, or 'unknown' on failure."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return "unknown"


def get_rust_toolchain() -> str:
    """Return the active Rust toolchain, or 'unknown' on failure."""
    try:
        result = subprocess.run(
            ["rustup", "show", "active-toolchain"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return "unknown"


def parse_fields_tuple(inner: str) -> list:
    """Parse comma-separated type list from a tuple variant interior."""
    fields = []
    # Split on top-level commas (respecting angle brackets for generics)
    depth = 0
    current = []
    for ch in inner:
        if ch in "<([":
            depth += 1
            current.append(ch)
        elif ch in ">)]":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            fields.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        tail = "".join(current).strip()
        if tail:
            fields.append(tail)
    return [
        {"position": i, "name": None, "type": t}
        for i, t in enumerate(fields)
    ]


def parse_fields_struct(inner: str) -> list:
    """Parse named fields from a struct variant interior."""
    fields = []
    # Simple field: `name: Type` separated by commas
    # We split on commas at depth 0
    depth = 0
    current = []
    for ch in inner:
        if ch in "<([{":
            depth += 1
            current.append(ch)
        elif ch in ">)]}":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            fields.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        tail = "".join(current).strip()
        if tail:
            fields.append(tail)

    result = []
    for i, f in enumerate(fields):
        m = re.match(r"^([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(.+)$", f.strip())
        if m:
            result.append({"position": i, "name": m.group(1), "type": m.group(2).strip()})
    return result


def extract_datakey_block(source: str) -> str:
    """Extract the body of `pub enum DataKey { ... }` from source text."""
    # Find the start of the enum
    pattern = re.compile(r"\bpub\s+enum\s+DataKey\s*\{")
    m = pattern.search(source)
    if not m:
        raise ValueError("Could not find `pub enum DataKey {` in the source file.")

    start = m.end()
    depth = 1
    i = start
    while i < len(source) and depth > 0:
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
        i += 1
    return source[start : i - 1]


def parse_variants(block: str) -> list:
    """
    Parse variants from the extracted DataKey enum block.
    Returns a list of variant dicts with ordinal, name, kind, fields, tombstone, comment.
    """
    variants = []
    ordinal = 0

    # We'll iterate line by line, tracking doc-comment accumulation
    lines = block.split("\n")
    pending_comments: list[str] = []

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Skip empty lines and non-doc comments (but reset pending comments on blank lines)
        if not stripped:
            # Blank line resets pending doc comments (they must be immediately above a variant)
            pending_comments = []
            i += 1
            continue

        # Section comment (// ...) — not a doc comment, skip
        if stripped.startswith("//") and not stripped.startswith("///"):
            # Non-doc comments don't attach to variants
            pending_comments = []
            i += 1
            continue

        # Doc comment
        if stripped.startswith("///"):
            comment_text = stripped[3:].strip()
            pending_comments.append(comment_text)
            i += 1
            continue

        # Attribute macros (e.g. #[deprecated]) — skip
        if stripped.startswith("#[") or stripped.startswith("#!["):
            i += 1
            continue

        # Try to match a variant declaration.
        # Variants may span multiple lines if they have struct bodies.
        # Collect full variant text (until we hit a comma at depth 0 or end of block).
        # First, we need to collect the full variant text across lines.
        variant_lines = [stripped]
        # Check if the current stripped line is a complete variant or needs more lines
        depth = variant_lines[0].count("{") - variant_lines[0].count("}")
        depth += variant_lines[0].count("(") - variant_lines[0].count(")")
        j = i + 1
        while depth > 0 and j < len(lines):
            next_stripped = lines[j].strip()
            variant_lines.append(next_stripped)
            depth += next_stripped.count("{") - next_stripped.count("}")
            depth += next_stripped.count("(") - next_stripped.count(")")
            j += 1

        variant_text = " ".join(variant_lines)
        # Remove trailing comma
        variant_text = variant_text.rstrip(",").strip()

        # Skip if this doesn't look like a variant (e.g. starts with // etc)
        if not variant_text or variant_text.startswith("//"):
            pending_comments = []
            i += 1
            continue

        # Try to parse the variant
        comment = " ".join(pending_comments).strip()
        pending_comments = []

        # Determine tombstone status
        tombstone = any(kw in comment.lower() for kw in TOMBSTONE_KEYWORDS)

        # Match variant patterns:
        # Unit:   Name
        # Tuple:  Name(T1, T2, ...)
        # Struct: Name { field: T, ... }

        # Struct variant
        struct_match = re.match(r"^([A-Za-z][A-Za-z0-9_]*)\s*\{(.+)\}$", variant_text, re.DOTALL)
        if struct_match:
            name = struct_match.group(1)
            tier = classify_tier(name, comment)
            inner = struct_match.group(2)
            fields = parse_fields_struct(inner)
            variants.append({
                "ordinal": ordinal,
                "name": name,
                "kind": "struct",
                "fields": fields,
                "tombstone": tombstone,
                "comment": comment,
                "tier": tier,
                "serialized_bytes": estimate_variant_size({"fields": fields}),
                "xdr_size_bytes": estimate_xdr_size(fields),
            })
            ordinal += 1
            i = j
            continue

        # Tuple variant
        tuple_match = re.match(r"^([A-Za-z][A-Za-z0-9_]*)\s*\((.+)\)$", variant_text, re.DOTALL)
        if tuple_match:
            name = tuple_match.group(1)
            tier = classify_tier(name, comment)
            inner = tuple_match.group(2)
            fields = parse_fields_tuple(inner)
            variants.append({
                "ordinal": ordinal,
                "name": name,
                "kind": "tuple",
                "fields": fields,
                "tombstone": tombstone,
                "comment": comment,
                "tier": tier,
                "serialized_bytes": estimate_variant_size({"fields": fields}),
                "xdr_size_bytes": estimate_xdr_size(fields),
            })
            ordinal += 1
            i = j
            continue

        # Unit variant
        unit_match = re.match(r"^([A-Za-z][A-Za-z0-9_]*)$", variant_text)
        if unit_match:
            name = unit_match.group(1)
            tier = classify_tier(name, comment)
            variants.append({
                "ordinal": ordinal,
                "name": name,
                "kind": "unit",
                "fields": [],
                "tombstone": tombstone,
                "comment": comment,
                "tier": tier,
                "serialized_bytes": estimate_variant_size({"fields": []}),
                "xdr_size_bytes": estimate_xdr_size([]),
            })
            ordinal += 1
            i = j
            continue

        # Didn't match — skip
        i += 1

    return variants


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract the DataKey enum from a Rust source file and emit a JSON snapshot."
    )
    parser.add_argument(
        "--source",
        default="src/lib.rs",
        help="Path to the Rust source file containing the DataKey enum (default: src/lib.rs)",
    )
    parser.add_argument(
        "--output",
        default="scripts/storage-layout/snapshots/current.json",
        help="Output JSON snapshot path (default: scripts/storage-layout/snapshots/current.json)",
    )
    parser.add_argument(
        "--contract",
        default="AuditLedger",
        help="Contract name to embed in the snapshot (default: AuditLedger)",
    )
    args = parser.parse_args()

    # Read source file
    source_path = Path(args.source)
    if not source_path.exists():
        print(f"ERROR: Source file not found: {source_path}", file=sys.stderr)
        return 1

    try:
        source = source_path.read_text(encoding="utf-8")
    except OSError as e:
        print(f"ERROR: Could not read source file: {e}", file=sys.stderr)
        return 1

    # Extract and parse
    try:
        block = extract_datakey_block(source)
        variants = parse_variants(block)
    except Exception as e:
        print(f"ERROR: Parsing failed: {e}", file=sys.stderr)
        return 1

    tombstone_count = sum(1 for v in variants if v["tombstone"])

    # Aggregate tier classification and byte budgets for the snapshot.
    tier_counts = {
        TIER_PERSISTENT: 0,
        TIER_TEMPORARY: 0,
        TIER_INSTANCE: 0,
        "persistent": 0,
        "temporary": 0,
        "instance": 0,
    }
    total_xdr_bytes = 0
    for v in variants:
        tier = v.get("tier", TIER_PERSISTENT)
        tier_counts[tier] = tier_counts.get(tier, 0) + 1
        tier_lower = tier.lower()
        if tier_lower in tier_counts:
            tier_counts[tier_lower] = tier_counts.get(tier_lower, 0) + 1
        total_xdr_bytes += v.get("xdr_size_bytes", v.get("serialized_bytes", 0))

    total_serialized_bytes = sum(v.get("serialized_bytes", 0) for v in variants)
    max_serialized_bytes = max(
        (v.get("serialized_bytes", 0) for v in variants), default=0
    )

    # Build snapshot
    snapshot = {
        "version": 2,
        "contract": args.contract,
        "generated_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "git_commit": get_git_commit(),
        "rust_toolchain": get_rust_toolchain(),
        "tier_counts": tier_counts,
        "total_serialized_bytes": total_serialized_bytes,
        "max_serialized_bytes": max_serialized_bytes,
        "total_xdr_size_bytes": total_xdr_bytes,
        "variants": variants,
    }

    # Write output
    output_path = Path(args.output)
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    except OSError as e:
        print(f"ERROR: Could not write output: {e}", file=sys.stderr)
        return 1

    print(
        f"Extracted {len(variants)} variants ({tombstone_count} tombstones) → {output_path}"
    )
    print(
        "Tier counts: "
        f"Persistent={tier_counts.get(TIER_PERSISTENT, 0)} "
        f"Temporary={tier_counts.get(TIER_TEMPORARY, 0)} "
        f"Instance={tier_counts.get(TIER_INSTANCE, 0)}"
    )
    print(
        f"Serialized byte budget: total={total_serialized_bytes} "
        f"max={max_serialized_bytes} (total XDR: {total_xdr_bytes} bytes)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
