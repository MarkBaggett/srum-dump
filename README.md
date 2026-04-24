# SRUM-DUMP (Version 3)

SRUM-DUMP extracts data from the System Resource Utilization Management (SRUM) database and generates an Excel spreadsheet or CSV. This tool is invaluable for forensic investigations, as SRUM maintains records of applications that have run on a system within the last 30 days.

## Features

- Extracts and analyzes data from `SRUDB.DAT`
- Generates an Excel workbook or CSV directory for easy analysis
- Supports enrichment using the SOFTWARE registry hive (network profiles, SIDs, table names)
- Automatically generates a configuration file on first run — edit it to add dirty words, custom translations, and formatting
- Dual ESE database engine support (`dissect` or `pyesedb`) for handling corrupt databases
- **Linux compatible** — core extraction works on Linux/macOS using the `dissect` engine; live file extraction remains Windows-only

## Download and Installation

A prebuilt Windows executable is available in the [Releases](https://github.com/MarkBaggett/srum-dump/releases) section.

To run from source (Windows or Linux):

```bash
git clone https://github.com/vividDuck/srum-dump.git
cd srum-dump
```

```bash
pip install -r requirements.txt
```

Python 3.12 or later is required.

## Running SRUM-DUMP

### GUI Mode (Windows only)

![SRUM-DUMP GUI](srum-dump-use.gif)

Launch the executable (or `python srum-dump/srum_dump.py` without arguments on Windows with a display). A wizard will guide you through:

1. **Select an output directory** — an empty directory where working files and results will be stored.
2. **Select the SRUDB.DAT file** — required. To analyse `C:\Windows\System32\sru\SRUDB.dat` on a live system, administrative privileges are required; the tool will extract a clean copy automatically via VSS.
3. **(Optional) Select the SOFTWARE registry hive** — enriches output with Wi-Fi network profile names, SID-to-username mappings, and SRUM extension table names.
4. **Review the configuration** — edit `srum_dump_config.json` in the output directory, then click **CONFIRM**.
5. The tool processes the database and writes output to the selected directory.

### CLI Mode

Supply all required arguments and pass `-q` to skip the confirmation dialog. This is the only mode available on Linux.

```
usage: srum_dump.py [-h] [-i SRUM_INFILE] [-o OUT_DIR] [-r REG_HIVE]
                    [-e {pyesedb,dissect}] [-f {xls,csv}] [-v] [-q]

options:
  -h, --help                          Show this help message and exit
  -i, --SRUM_INFILE SRUM_INFILE       Path to the ESE database file (SRUDB.dat)
  -o, --OUT_DIR OUT_DIR               Output directory (created if it does not exist)
  -r, --REG_HIVE REG_HIVE             Path to a SOFTWARE registry hive (optional)
  -e, --ESE_ENGINE {pyesedb,dissect}  Database engine — try the other if one fails on a corrupt file (default: dissect)
  -f, --OUTPUT_FORMAT {xls,csv}       Output format (default: xls)
  -v, --DEBUG                         Write verbose debug log to srum_dump.log
  -q, --NO_CONFIRM                    Skip the GUI confirmation dialog (required in headless/Linux mode)
```

#### Examples

**Basic extraction to Excel (Linux / macOS):**
```bash
python srum-dump/srum_dump.py \
  -i /cases/host01/SRUDB.dat \
  -o /cases/host01/srum_output \
  -q
```

**With SOFTWARE hive for enriched output:**
```bash
python srum-dump/srum_dump.py \
  -i /cases/host01/SRUDB.dat \
  -o /cases/host01/srum_output \
  -r /cases/host01/SOFTWARE \
  -q
```

**Export to CSV instead of Excel:**
```bash
python srum-dump/srum_dump.py \
  -i /cases/host01/SRUDB.dat \
  -o /cases/host01/srum_output \
  -f csv \
  -q
```

**Try the alternate engine on a corrupt database:**
```bash
python srum-dump/srum_dump.py \
  -i /cases/host01/SRUDB.dat \
  -o /cases/host01/srum_output \
  -e pyesedb \
  -q
```

**Windows CLI — live system extraction (run as Administrator):**
```powershell
.\srum_dump.exe -i C:\Windows\System32\sru\SRUDB.dat -o C:\cases\host01 -q
```
The tool detects that the file is locked, creates a VSS snapshot, extracts a clean copy, and processes it automatically.

### Output

On the first run, the tool creates `srum_dump_config.json` in the output directory. Subsequent runs reuse and update this file. Results are written to a timestamped file or directory alongside the config:

| Format | Output |
|--------|--------|
| `xls`  | `SRUM-DUMP-<timestamp>.xlsx` |
| `csv`  | `SRUM-DUMP-<timestamp>/` directory containing one CSV per SRUM table |

A log file (`srum_dump.log`) is always written to the output directory. Pass `-v` for verbose debug output.

## Configuration File

`srum_dump_config.json` is generated automatically and can be edited between runs to customise the analysis. See [configuration_file.md](configuration_file.md) for the full specification. Key sections:

| Section | Purpose |
|---------|---------|
| `dirty_words` | Strings to highlight in the output (map word → style name) |
| `known_sids` | SID-to-username mappings (pre-populated with well-known SIDs; extended from registry) |
| `known_tables` | Maps internal GUIDs to human-readable SRUM table names |
| `network_interfaces` | Maps network profile IDs to friendly names (populated from registry) |
| `column_markups` | Per-column formatting, translation type, width, and style |
| `SRUDbIdMapTable` | Full app/user ID dictionary extracted from the database |

## Dependencies

Installed automatically via `requirements.txt` / `requirements-linux.txt`:

| Library | Purpose |
|---------|---------|
| [dissect.esedb](https://github.com/fox-it/dissect) | Primary ESE database parser (cross-platform) |
| [pylibesedb](https://github.com/log2timeline/l2tbinaries) | Alternate ESE parser (Windows precompiled wheel bundled) |
| [openpyxl](https://pypi.org/project/openpyxl/) / [XlsxWriter](https://pypi.org/project/XlsxWriter/) | Excel output |
| [python-registry](https://github.com/williballenthin/python-registry) | Registry hive parsing |
| [PyYAML](https://pypi.org/project/PyYAML/) | Config file support |
| pywin32 | Windows-only live file extraction (skipped on Linux/macOS) |

## Contributing

Contributions are welcome. Feel free to submit issues, feature requests, or pull requests. Please ensure new code is tested before submission.

## License

This project is released under the [GNU GPL](LICENSE).
