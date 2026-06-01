# Nessus Plugin Output Parser

A Python tool that extracts structured data from Nessus plugin output text using regex patterns defined in a YAML configuration file. Works as both a **CLI tool** and an **importable library**.

## Features

- Extract any field from Nessus plugin output using named regex capture groups
- YAML-driven configuration — add or adjust fields without changing code
- Supports raw plugin text (file or stdin) and full `.nessus` XML export files
- Two field definition styles: compact single-line and full extended form
- Returns a clean `{key: value}` dict from the core function, ready for use as a library
- Built-in demo mode with sample data for testing

## Requirements

- Python 3.10+
- [PyYAML](https://pypi.org/project/PyYAML/)

```bash
pip install pyyaml
```

## Files

```
.
├── nessus_parser.py           # Main application and importable library
├── config.yaml                # Plugin extraction rules
├── sample_plugin_outputs.txt  # Example plugin output text for manual testing
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

---

## Configuration

All extraction rules live in `config.yaml`. No code changes are needed to add, remove, or adjust fields.

### Structure

```yaml
plugins:
  - plugin_id: "<nessus plugin ID>"   # string, must match Nessus output
    name:      "<human-readable label>"
    fields:
      <key>: "<regex with one capture group>"  # simple form
      <key>:                                   # extended form
        pattern:     "<regex>"
        group:       <capture group number, default 1>
        multiple:    <true = findall, false = first match only>
        ignore_case: <true/false>
        multiline:   <true/false>
```

### Field Definition — Simple Form

When the value is a plain string it is treated as a regex pattern. Capture group 1 is returned.

```yaml
fields:
  cnname: "Subject Name:[\\s\\S]*?Common Name\\s*:\\s*(.+)"
  serial: "Serial Number\\s*:\\s*([0-9a-fA-F:]+)"
```

### Field Definition — Extended Form

Use a mapping when you need options beyond the defaults:

```yaml
fields:
  san_entries:
    pattern:     "DNS:([^,\n]+)"  # regex with one capture group
    group:       1                # which capture group to return (default: 1)
    multiple:    true             # true = findall (list), false = first match
    ignore_case: false            # re.IGNORECASE (default: false)
    multiline:   false            # re.MULTILINE (default: false)
```

### Field Options Reference

| Option | Type | Default | Description |
|---|---|---|---|
| `pattern` | string | — | Regex with at least one capture group |
| `group` | int | `1` | Capture group index to extract |
| `multiple` | bool | `false` | `true` returns all non-overlapping matches as a list |
| `ignore_case` | bool | `false` | Enables case-insensitive matching (`re.IGNORECASE`) |
| `multiline` | bool | `false` | Enables multiline mode (`re.MULTILINE`); `^` and `$` match line edges |

### Return Values

| Scenario | Returned value |
|---|---|
| Pattern matched, `multiple: false` | `str` — captured text, whitespace-stripped |
| Pattern matched, `multiple: true` | `list[str]` — all captures, each stripped |
| No match, `multiple: false` | `None` |
| No match, `multiple: true` | `[]` |

### Example: Adding a New Plugin

1. Find the plugin ID in Nessus (scan results or the plugin library).
2. Copy a sample of the plugin's raw output text.
3. Add an entry to `config.yaml`:

```yaml
  - plugin_id: "YOUR_PLUGIN_ID"
    name: "Human Readable Name"
    fields:
      field_one: "regex with (one capture group)"
      field_two:
        pattern:  "regex with (capture group)"
        multiple: true
```

4. Test with `text` mode:

```bash
cat sample.txt | python nessus_parser.py text -p YOUR_PLUGIN_ID
```

### Built-in Plugins

The default `config.yaml` includes rules for four common plugins:

| Plugin ID | Name | Extracted Fields |
|---|---|---|
| `10863` | SSL Certificate Information | `cnname`, `issuer`, `valid_from`, `valid_to`, `serial`, `san_entries` |
| `11936` | OS Identification | `os`, `confidence` |
| `10180` | Ping the Remote Host | `response_time`, `icmp_seq` |
| `19506` | Nessus Scan Information | `scanner_ip`, `scan_start`, `scan_end`, `policy`, `nessus_version` |

---

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
  -p, --plugin-id   Nessus plugin ID (required)
  -f, --file        Input file; omit to read from stdin
```

**xml mode**

```
usage: nessus_parser xml [-h] -f FILE

options:
  -f, --file   Path to the .nessus XML file (required)
```

**demo mode**

Runs against built-in sample data. No input file required. Useful for verifying that your `config.yaml` parses correctly.

---

## Using as a Library

### Parse a single plugin output

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
#   'cnname':      'www.example.com',
#   'issuer':      'DigiCert SHA2 Secure Server CA',
#   'valid_from':  'Jan 10 00:00:00 2024 GMT',
#   'valid_to':    'Jan 10 23:59:59 2025 GMT',
#   'serial':      '0a:1b:2c:3d:4e:5f',
#   'san_entries': []
# }
```

`parse_plugin_output` raises `KeyError` if `plugin_id` is not present in the configuration.

### Function signature

```python
def parse_plugin_output(
    plugin_output: str,
    plugin_id: str,
    config: dict,
) -> dict[str, str | list[str] | None]:
    ...
```

### Parse a `.nessus` XML export

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
| `protocol` | Protocol (`tcp` / `udp`) |
| `extracted_fields` | `dict` of key → value as returned by `parse_plugin_output` |

---

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

---

## Troubleshooting

**`[ERROR] Config file not found`**
Pass the correct path with `-c /path/to/config.yaml`.

**`KeyError: Plugin ID 'XXXXX' is not defined`**
Add a `plugin_id: "XXXXX"` entry to `config.yaml`.

**Field value is `None` or `[]` when you expect a match**
- Test your regex against the raw plugin text using a tool like [regex101.com](https://regex101.com) (Python flavour).
- Make sure capture group 1 exists — every pattern needs at least one `( )` group.
- If the field spans multiple lines, set `multiline: true`.
- If casing varies, set `ignore_case: true`.

**`[WARNING] Bad regex for key 'X'`**
The pattern string contains a syntax error. Check for unbalanced parentheses or unescaped backslashes. In YAML, backslashes inside double-quoted strings must be doubled (`\\`).
