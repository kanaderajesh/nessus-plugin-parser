# Nessus Plugin Output Parser

A console-based Python tool that extracts structured data from Nessus plugin output text using regex patterns defined in a YAML configuration file.

## Features

- Extract any field from a Nessus plugin output using named regex capture groups
- YAML-driven configuration — no code changes needed to add or adjust fields
- Supports both raw plugin text and full `.nessus` XML export files
- Two field definition styles: a compact single-line form and a full extended form
- Returns a clean `{key: value}` dictionary from the core function, suitable for use as a library

## Requirements

- Python 3.10+
- [PyYAML](https://pypi.org/project/PyYAML/)

```bash
pip install pyyaml
```

## Files

```
.
├── nessus_parser.py          # Main application and library
├── config.yaml               # Plugin extraction rules
├── sample_plugin_outputs.txt # Example plugin output text for testing
└── README.md
```

## Quick Start

```bash
# Run the built-in demo (no input file needed)
python nessus_parser.py demo

# Parse a specific plugin's raw text file
python nessus_parser.py text -p 10863 -f plugin_output.txt

# Pipe plugin output from stdin
cat output.txt | python nessus_parser.py text -p 10863

# Parse a full .nessus XML export
python nessus_parser.py xml -f report.nessus

# Use a custom config file
python nessus_parser.py -c my_config.yaml demo
```

## Configuration File

`config.yaml` maps plugin IDs to the fields you want to extract. Each field is a named regex pattern that captures the value for that key.

### Minimal structure

```yaml
plugins:
  - plugin_id: "10863"
    name: "SSL Certificate Information"
    fields:
      cnname:    "Subject Name:[\\s\\S]*?Common Name\\s*:\\s*(.+)"
      valid_to:  "Not After\\s*:\\s*(.+)"
      serial:    "Serial Number\\s*:\\s*([0-9a-fA-F:]+)"
```

### Field definition: simple form

When the value is a plain string, it is treated as a regex pattern. Group 1 is captured and assigned to the key.

```yaml
fields:
  cnname: "Subject Name:[\\s\\S]*?Common Name\\s*:\\s*(.+)"
  serial: "Serial Number\\s*:\\s*([0-9a-fA-F:]+)"
```

### Field definition: extended form

Use a mapping when you need extra options:

```yaml
fields:
  san_entries:
    pattern:     "DNS:([^,\n]+)"   # regex with one capture group
    group:       1                 # which capture group to return (default: 1)
    multiple:    true              # true = findall (returns a list), false = first match
    ignore_case: false             # case-insensitive matching (default: false)
    multiline:   false             # dot matches newline, ^ and $ match line edges (default: false)
```

| Option | Type | Default | Description |
|---|---|---|---|
| `pattern` | string | — | Regex with at least one capture group |
| `group` | int | `1` | Capture group number to return |
| `multiple` | bool | `false` | `true` returns all matches as a list |
| `ignore_case` | bool | `false` | Case-insensitive flag (`re.IGNORECASE`) |
| `multiline` | bool | `false` | Multiline / dotall flags (`re.MULTILINE`) |

### Return values

| Scenario | Returned value |
|---|---|
| Pattern matched, `multiple: false` | `str` — the captured text, whitespace-stripped |
| Pattern matched, `multiple: true` | `list[str]` — all captures, each stripped |
| Pattern not found | `None` (simple) or `[]` (multiple) |

## Using as a Library

The core function can be imported directly into your own scripts:

```python
from nessus_parser import load_config, parse_plugin_output

config = load_config("config.yaml")

plugin_output = """
Subject Name:
  Common Name: www.example.com
Issuer Name:
  Common Name: DigiCert SHA2 Secure Server CA
Not Before: Jan 10 00:00:00 2024 GMT
Not After : Jan 10 23:59:59 2025 GMT
Serial Number: 0a:1b:2c:3d:4e:5f
"""

result = parse_plugin_output(plugin_output, plugin_id="10863", config=config)
print(result)
# {
#   'cnname':     'www.example.com',
#   'issuer':     'DigiCert SHA2 Secure Server CA',
#   'valid_from': 'Jan 10 00:00:00 2024 GMT',
#   'valid_to':   'Jan 10 23:59:59 2025 GMT',
#   'serial':     '0a:1b:2c:3d:4e:5f',
#   'san_entries': []
# }
```

### `parse_plugin_output` signature

```python
def parse_plugin_output(
    plugin_output: str,
    plugin_id: str,
    config: dict,
) -> dict[str, str | list[str] | None]:
    ...
```

Raises `KeyError` if `plugin_id` is not present in the configuration.

### Parsing a `.nessus` XML file

```python
from nessus_parser import load_config, parse_nessus_xml

config  = load_config("config.yaml")
results = parse_nessus_xml("report.nessus", config)

for r in results:
    print(r["host"], r["plugin_id"], r["extracted_fields"])
```

Each entry in the returned list contains:

| Key | Description |
|---|---|
| `host` | Hostname from the `<ReportHost>` element |
| `plugin_id` | Nessus plugin ID string |
| `plugin_name` | Plugin name from the XML |
| `port` | Port number |
| `protocol` | Protocol (tcp / udp) |
| `extracted_fields` | `dict` of key → value, as returned by `parse_plugin_output` |

## CLI Reference

```
usage: nessus_parser [-h] [-c CONFIG] MODE ...

positional arguments:
  MODE
    text    Parse a raw plugin output text (file or stdin)
    xml     Parse a .nessus XML export file
    demo    Run against built-in sample data

options:
  -h, --help      show this help message and exit
  -c, --config    Path to YAML config file (default: config.yaml)
```

**text mode**

```
usage: nessus_parser text [-h] -p PLUGIN_ID [-f FILE]

options:
  -p, --plugin-id   Nessus plugin ID to use for extraction (required)
  -f, --file        Input file; omit to read from stdin
```

**xml mode**

```
usage: nessus_parser xml [-h] -f FILE

options:
  -f, --file   Path to the .nessus XML file (required)
```

## Adding a New Plugin

1. Find the plugin ID in Nessus (visible in scan results or the plugin library).
2. Copy a sample of the plugin's output text.
3. Add a new entry to `config.yaml`:

```yaml
  - plugin_id: "YOUR_PLUGIN_ID"
    name: "Human Readable Name"
    fields:
      field_one: "regex with (one capture group)"
      field_two:
        pattern:  "regex with (capture group)"
        multiple: true
```

4. Test with the `text` mode:

```bash
cat sample.txt | python nessus_parser.py text -p YOUR_PLUGIN_ID
```

## Example Output

```
==============================================================
  Host      : 192.168.1.10
  Plugin ID : 10863
  Plugin    : SSL Certificate Information
──────────────────────────────────────────────────────────────
  Extracted Fields:
  cnname: www.example.com
  issuer: DigiCert SHA2 Secure Server CA
  valid_from: Jan 10 00:00:00 2024 GMT
  valid_to: Jan 10 23:59:59 2025 GMT
  serial: 0a:1b:2c:3d:4e:5f:6a:7b
  san_entries:
    - www.example.com
    - example.com
    - api.example.com
==============================================================
  Total records : 1
==============================================================
```
