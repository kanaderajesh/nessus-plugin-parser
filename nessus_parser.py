#!/usr/bin/env python3
"""
Nessus Plugin Output Parser
============================
Parses Nessus plugin output text and extracts fields via regex patterns
defined in a YAML configuration file.

Usage:
  # Parse raw plugin text from a file
  python nessus_parser.py text -c config.yaml -p 10863 -f plugin_output.txt

  # Pipe plugin text through stdin
  cat plugin_output.txt | python nessus_parser.py text -c config.yaml -p 10863

  # Parse a .nessus XML export (extracts every configured plugin)
  python nessus_parser.py xml -c config.yaml -f report.nessus

  # Parse the bundled sample file (for demo / testing)
  python nessus_parser.py demo -c config.yaml
"""

import re
import sys
import argparse
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    sys.exit("[ERROR] PyYAML is required.  Install it with:  pip install pyyaml")


# ──────────────────────────────────────────────────────────────────────────────
# Configuration loader
# ──────────────────────────────────────────────────────────────────────────────

def load_config(config_path: str) -> dict:
    """Load and perform basic validation on the YAML configuration file."""
    path = Path(config_path)
    if not path.exists():
        sys.exit(f"[ERROR] Config file not found: {config_path}")

    with path.open("r") as fh:
        try:
            config = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            sys.exit(f"[ERROR] Invalid YAML in config file: {exc}")

    if not isinstance(config, dict) or "plugins" not in config:
        sys.exit("[ERROR] Config file must have a top-level 'plugins' key.")

    return config


def _build_plugin_index(config: dict) -> dict[str, dict]:
    """Return a dict keyed by plugin_id string for fast lookups."""
    index: dict[str, dict] = {}
    for plugin in config.get("plugins", []):
        pid = str(plugin.get("plugin_id", "")).strip()
        if pid:
            index[pid] = plugin
    return index


# ──────────────────────────────────────────────────────────────────────────────
# Text helpers
# ──────────────────────────────────────────────────────────────────────────────

def _collapse_continuation_lines(text: str) -> str:
    """Join lines that start with whitespace onto the preceding line.

    Nessus sometimes wraps long values (e.g. SHA-256 fingerprints) onto a
    second line that is indented with leading spaces.  This merges those
    continuation lines so a single-line regex can match the full value.
    """
    lines = text.splitlines()
    merged: list[str] = []
    for line in lines:
        if line and line[0].isspace() and merged:
            merged[-1] = merged[-1].rstrip() + " " + line.strip()
        else:
            merged.append(line)
    return "\n".join(merged)


# ──────────────────────────────────────────────────────────────────────────────
# Core extraction function
# ──────────────────────────────────────────────────────────────────────────────

def parse_plugin_output(plugin_output: str, plugin_id: str, config: dict) -> dict[str, Any]:
    """
    Extract fields from *plugin_output* using the patterns defined in *config*
    for the given *plugin_id*.

    Parameters
    ----------
    plugin_output : str
        Raw text output of a single Nessus plugin result.
    plugin_id : str
        The Nessus plugin ID (e.g. "10863").
    config : dict
        Parsed YAML configuration (result of load_config).

    Returns
    -------
    dict
        Mapping of field-key → extracted value (str) or list[str] when
        ``multiple: true`` is set, or ``None`` when the pattern found nothing.

    Raises
    ------
    KeyError
        If *plugin_id* is not present in the configuration.
    """
    plugin_index = _build_plugin_index(config)
    pid = str(plugin_id).strip()

    if pid not in plugin_index:
        raise KeyError(
            f"Plugin ID '{pid}' is not defined in the configuration file. "
            f"Available IDs: {sorted(plugin_index.keys())}"
        )

    plugin_cfg = plugin_index[pid]
    fields: dict[str, Any] = plugin_cfg.get("fields", {})
    results: dict[str, Any] = {}

    for key, field_def in fields.items():
        # ── Resolve pattern and options ────────────────────────────────────
        if isinstance(field_def, str):
            # Simple form:  key: "regex"
            pattern = field_def
            group = 1
            multiple = False
            collapse_lines = False
            re_flags = 0
        elif isinstance(field_def, dict):
            # Extended form
            pattern = field_def.get("pattern", "")
            group = int(field_def.get("group", 1))
            multiple = bool(field_def.get("multiple", False))
            collapse_lines = bool(field_def.get("collapse_lines", False))
            re_flags = 0
            if field_def.get("ignore_case", False):
                re_flags |= re.IGNORECASE
            if field_def.get("multiline", False):
                re_flags |= re.MULTILINE
        else:
            print(f"  [WARNING] Skipping key '{key}': unexpected field definition type.", file=sys.stderr)
            results[key] = None
            continue

        if not pattern:
            print(f"  [WARNING] Skipping key '{key}': empty pattern.", file=sys.stderr)
            results[key] = None
            continue

        # ── Optionally merge wrapped continuation lines ─────────────────────
        text = _collapse_continuation_lines(plugin_output) if collapse_lines else plugin_output

        # ── Apply regex ────────────────────────────────────────────────────
        try:
            if multiple:
                # Return every non-overlapping capture
                matches = re.findall(pattern, text, re_flags)
                # re.findall returns strings when there is one group,
                # tuples when there are multiple groups.
                if matches and isinstance(matches[0], tuple):
                    matches = [m[group - 1] for m in matches]
                results[key] = [m.strip() for m in matches]
            else:
                match = re.search(pattern, text, re_flags)
                results[key] = match.group(group).strip() if match else None
        except re.error as exc:
            print(f"  [WARNING] Bad regex for key '{key}': {exc}", file=sys.stderr)
            results[key] = None
        except IndexError:
            print(f"  [WARNING] Group {group} does not exist in pattern for key '{key}'.", file=sys.stderr)
            results[key] = None

    return results


# ──────────────────────────────────────────────────────────────────────────────
# .nessus XML parser (wraps parse_plugin_output per ReportItem)
# ──────────────────────────────────────────────────────────────────────────────

def parse_nessus_xml(xml_path: str, config: dict) -> list[dict]:
    """
    Walk a *.nessus* XML export and call :func:`parse_plugin_output` for every
    ``<ReportItem>`` whose ``pluginID`` is in the configuration.

    Parameters
    ----------
    xml_path : str
        Path to the ``.nessus`` file.
    config : dict
        Parsed YAML configuration.

    Returns
    -------
    list[dict]
        Each entry contains host metadata and an ``extracted_fields`` sub-dict.
    """
    plugin_index = _build_plugin_index(config)

    try:
        tree = ET.parse(xml_path)
    except FileNotFoundError:
        sys.exit(f"[ERROR] File not found: {xml_path}")
    except ET.ParseError as exc:
        sys.exit(f"[ERROR] Failed to parse XML file: {exc}")

    root = tree.getroot()
    results: list[dict] = []

    for report_host in root.iter("ReportHost"):
        hostname = report_host.get("name", "unknown")

        for item in report_host.iter("ReportItem"):
            pid = item.get("pluginID", "")
            if pid not in plugin_index:
                continue

            output_elem = item.find("plugin_output")
            plugin_output = output_elem.text.strip() if (output_elem is not None and output_elem.text) else ""

            extracted = parse_plugin_output(plugin_output, pid, config)

            results.append({
                "host":            hostname,
                "plugin_id":       pid,
                "plugin_name":     item.get("pluginName", plugin_index[pid].get("name", "")),
                "port":            item.get("port", ""),
                "protocol":        item.get("protocol", ""),
                "extracted_fields": extracted,
            })

    return results


# ──────────────────────────────────────────────────────────────────────────────
# Display helpers
# ──────────────────────────────────────────────────────────────────────────────

def _display_fields(fields: dict[str, Any], indent: int = 2) -> None:
    pad = " " * indent
    for key, value in fields.items():
        if isinstance(value, list):
            if value:
                print(f"{pad}{key}:")
                for item in value:
                    print(f"{pad}  - {item}")
            else:
                print(f"{pad}{key}: (no matches)")
        else:
            display_val = value if value is not None else "(not found)"
            print(f"{pad}{key}: {display_val}")


def display_results(results: list[dict] | dict) -> None:
    """Pretty-print one or more extraction result dicts."""
    if isinstance(results, dict):
        results = [results]

    for i, result in enumerate(results, start=1):
        sep = "=" * 62
        print(f"\n{sep}")

        has_meta = "host" in result
        if has_meta:
            print(f"  Host      : {result['host']}")
            print(f"  Plugin ID : {result['plugin_id']}")
            print(f"  Plugin    : {result['plugin_name']}")
            if result.get("port"):
                print(f"  Port      : {result['port']}/{result['protocol']}")
            print(f"{'─' * 62}")

        print("  Extracted Fields:")
        fields = result.get("extracted_fields", result)
        _display_fields(fields)

    print(f"\n{'=' * 62}")
    print(f"  Total records : {len(results)}")
    print(f"{'=' * 62}\n")


# ──────────────────────────────────────────────────────────────────────────────
# Demo mode – parse the bundled sample file
# ──────────────────────────────────────────────────────────────────────────────

_SAMPLE_PLUGIN_BLOCKS = {
    "10863": r"""
Subject Name:
  Country: US
  State/Province: California
  Locality: San Francisco
  Organization: Example Corp
  Common Name: www.example.com

Issuer Name:
  Country: US
  Organization: DigiCert Inc
  Common Name: DigiCert SHA2 Secure Server CA

Serial Number: 00 D3 9F A4 B8 28 D5 05 27

Not Before: Jan 10 00:00:00 2024 GMT
Not After : Jan 10 23:59:59 2025 GMT

SHA-256 Fingerprint: 34 3C 4E 48 E2 E6 84 AF A3 AA B0 02 97 96 63 C7 5B E3 37 25
                     E7 3D C0 02 A1 2E C0 E1 31 75 34 07

Subject Alternative Names:
  DNS:www.example.com
  DNS:example.com
  DNS:api.example.com
""",
    "11936": r"""
Remote operating system : Linux Kernel 5.15 on Ubuntu 22.04 LTS
Confidence level        : 95
Method                  : SSH
""",
    "19506": r"""
Nessus version            : 10.6.2
Scanner IP                : 192.168.1.50
Scan policy used          : Basic Network Scan
Scan Start Date           : 2024/01/10 09:00 UTC
Scan End Date             : 2024/01/10 09:45 UTC
""",
}


def run_demo(config: dict) -> None:
    plugin_index = _build_plugin_index(config)
    configured_ids = sorted(plugin_index.keys())

    print("\n[DEMO] Running against built-in sample plugin outputs.")
    print(f"[DEMO] Configured plugin IDs: {configured_ids}\n")

    all_results = []
    for pid, sample_text in _SAMPLE_PLUGIN_BLOCKS.items():
        if pid not in plugin_index:
            print(f"[DEMO] Skipping plugin {pid} — not in config.")
            continue
        try:
            fields = parse_plugin_output(sample_text, pid, config)
            all_results.append({
                "host":            "demo-host",
                "plugin_id":       pid,
                "plugin_name":     plugin_index[pid].get("name", ""),
                "port":            "",
                "protocol":        "",
                "extracted_fields": fields,
            })
        except KeyError as exc:
            print(f"[DEMO] {exc}", file=sys.stderr)

    display_results(all_results)


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="nessus_parser",
        description="Extract fields from Nessus plugin output using YAML-defined regex patterns.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument(
        "-c", "--config",
        default="config.yaml",
        metavar="CONFIG",
        help="Path to YAML configuration file (default: config.yaml)",
    )

    sub = ap.add_subparsers(dest="mode", metavar="MODE")

    # ── text mode ─────────────────────────────────────────────────────────────
    tp = sub.add_parser("text", help="Parse a raw plugin output text (file or stdin)")
    tp.add_argument(
        "-p", "--plugin-id",
        required=True,
        metavar="PLUGIN_ID",
        help="Nessus plugin ID to use for field extraction",
    )
    tp.add_argument(
        "-f", "--file",
        metavar="FILE",
        help="Path to file containing plugin output (omit to read from stdin)",
    )

    # ── xml mode ──────────────────────────────────────────────────────────────
    xp = sub.add_parser("xml", help="Parse a .nessus XML export file")
    xp.add_argument(
        "-f", "--file",
        required=True,
        metavar="FILE",
        help="Path to the .nessus XML file",
    )

    # ── demo mode ─────────────────────────────────────────────────────────────
    sub.add_parser("demo", help="Run against built-in sample data (no input file needed)")

    return ap


def main() -> None:
    ap = build_arg_parser()
    args = ap.parse_args()

    if not args.mode:
        ap.print_help()
        sys.exit(0)

    config = load_config(args.config)

    # ── demo ──────────────────────────────────────────────────────────────────
    if args.mode == "demo":
        run_demo(config)
        return

    # ── xml ───────────────────────────────────────────────────────────────────
    if args.mode == "xml":
        results = parse_nessus_xml(args.file, config)
        if not results:
            print("[INFO] No matching plugin outputs found in the XML file.")
        else:
            print(f"[INFO] Extracted data from {len(results)} plugin result(s).")
            display_results(results)
        return

    # ── text ──────────────────────────────────────────────────────────────────
    if args.mode == "text":
        if args.file:
            path = Path(args.file)
            if not path.exists():
                sys.exit(f"[ERROR] File not found: {args.file}")
            plugin_text = path.read_text()
        else:
            print("[INFO] Reading plugin output from stdin (Ctrl-D / Ctrl-Z to finish)…",
                  file=sys.stderr)
            plugin_text = sys.stdin.read()

        try:
            fields = parse_plugin_output(plugin_text, args.plugin_id, config)
        except KeyError as exc:
            sys.exit(f"[ERROR] {exc}")

        display_results(fields)
        return


if __name__ == "__main__":
    main()
