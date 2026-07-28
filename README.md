# SRUM-DUMP (Version 3)

SRUM-DUMP extracts data from the System Resource Utilization Management (SRUM) database and generates an Excel spreadsheet. This tool is invaluable for forensic investigations, as SRUM maintains records of applications that have run on a system within the last 30 days.

## Features
- Extracts and analyzes data from `SRUDB.DAT`
- Generates an Excel report for easy analysis
- Supports additional enrichment using the SOFTWARE registry hive
- After initial analysis is done a configuration file is generated
- Edit the config file to indicate "dirty-words" and other elements of investigation 
- Provides a configuration file for fine-tuned extraction

## Download and Installation
A prebuilt version of SRUM-DUMP is available for download in the [Releases](https://github.com/MarkBaggett/srum-dump/releases) section.

Alternatively, you can clone and run the project from the source code.

## Running SRUM-DUMP
### Using the Prebuilt Tool GUI
![SRUM-DUMP GUI](srum-dump-use.gif)

1. **Launch the tool**: Run the executable.
2. **Select an output directory**: Choose an empty directory where the working files and results will be stored. 
3. **Select the SRUDB.DAT file**:
   - This is a required file.
   - If selecting `C:\Windows\System32\sru\srudb.dat` on a live system, administrative privileges are required.
4. **(Optional) Select the SOFTWARE registry hive**:
   - This file provides useful additional context.
   - If unavailable, leave this field blank.
5. **Confirm Configuration**:
   - Edit the configuration file to fine-tune the analysis (see [configuration_file.md](configuration_file.md)).
   - Click "CONFIRM" to proceed.
6. **Run the analysis**:
   - The tool will process the data and generate the output.
   - A progress dialog will appear, and the "Close" button will be disabled until the process completes.

The resulting files are in the specified output directory.

### Using the Prebuilt Tool CLI

You can specify each of the arguments from the CLI along for automated processing.

```
 .\srum_dump.exe -h
usage: srum_dump.exe [-h] [--SRUM_INFILE SRUM_INFILE] [--OUT_DIR OUT_DIR] [--REG_HIVE REG_HIVE] [--ESE_ENGINE {pyesedb,dissect}]
                     [--OUTPUT_FORMAT {xls,csv}] [--DEBUG] [--NO_CONFIRM]

Given an SRUM database it will create an XLS spreadsheet or CSV with analysis of the data in the database.

options:
  -h, --help            show this help message and exit
  --SRUM_INFILE SRUM_INFILE, -i SRUM_INFILE
                        Specify the ESE (.dat) file to analyze. Provide a valid path to the file.
  --OUT_DIR OUT_DIR, -o OUT_DIR
                        Full path to a working output directory.
  --REG_HIVE REG_HIVE, -r REG_HIVE
                        If SOFTWARE registry hive is provided then the names of the network profiles will be resolved.
  --ESE_ENGINE {pyesedb,dissect}, -e {pyesedb,dissect}
                        Corrupt file? Try a different engine to see if it does better. Options are pyesedb or dissect
  --OUTPUT_FORMAT {xls,csv}, -f {xls,csv}
                        Specify the output format. Options are xls or csv. Default is xls.
  --DEBUG, -v           Enable verbose logging in srum_dump.log
  --NO_CONFIRM, -q      Do not show the confirmation dialog box.
```

### Running from Source Code
This project requires **Python 3.12**.

#### Installation Steps:
```bash
git clone --branch version3 https://github.com/markbaggett/srum-dump.git
cd srum-dump
pip install -r requirements.txt
```

## FastMCP SQLite Converter

The MCP module can convert SRUM ESE data into an enriched SQLite database while preserving the existing SRUM-DUMP wrapper conversions and registry lookups.

```python
from srum_mcp_query import SRUM_to_SQLITE3

sqlite_path = SRUM_to_SQLITE3(
   r"C:\Evidence\SRUDB.dat",
   r"C:\Evidence\srum.sqlite3",
   registry_path=r"C:\Evidence\SOFTWARE",
   engine="dissect",
   overwrite=True,
)
```

`registry_path` is optional for offline evidence, but providing the SOFTWARE hive enriches SIDs, network profiles, interface names, and registry-derived SRUM table names. The default ESE engine is `dissect`; pass `engine="pyesedb"` to use the alternate wrapper.

If `srum_path` points to the live Windows database under `%SystemRoot%`, for example `C:\Windows\System32\sru\SRUDB.dat`, the converter requires administrator rights and uses the existing VSS copy helpers to extract both `SRUDB.dat` and `SOFTWARE` before conversion. Non-admin live conversion raises a clear `PermissionError`; offline SRUM files do not trigger VSS extraction.

The SQLite output stores raw SRUM tables plus translated companion columns such as `appid_resolved`, `userid_resolved`, `l2profileid_resolved`, and timestamp-normalized values where configured. Metadata tables including `srum_tables`, `srum_columns`, `srum_id_map`, `srum_network_interfaces`, `srum_interface_types`, and `srum_conversion_info` record the original GUIDs, display names, lookup data, and conversion settings.

The MCP server also exposes two general inspection tools:

- `query_database_read_only` runs one guarded `SELECT` or `WITH` query against the SRUM SQLite database. The connection is opened read-only, SQLite `query_only` mode is enabled, and mutating SQL keywords are rejected.
- `explain_database_schema` describes tables, row counts, original SRUM GUIDs/display names, converted SQLite columns, resolved companion columns, and table-content descriptions.

SRUM-specific query tools include process, file, network, Wi-Fi, PID, top CPU, top network byte, and user activity summary lookups. Any tool with `start_time` and `end_time` parameters treats both bounds as optional; omitting either bound leaves that side of the time range open, and omitting both searches all available dates. User-scoped helpers `query_processes_by_user_in_time_range`, `query_process_summary_by_user_in_time_range`, `query_files_by_user_in_time_range`, and `query_file_summary_by_user_in_time_range` accept a SID, account name, or resolved-user fragment such as `alice`.

To run the MCP server from source:

```bash
cd srum-dump
python srum-dump/srum_mcp_query.py
```

## SRUM Agent

`srum-agent.py` is a terminal-first local LLM assistant for SRUM investigations. It accepts familiar SRUM-DUMP CLI arguments, configures a remote or local inference runtime before conversion starts, converts the SRUM ESE database to the enriched SQLite format through `SRUM_to_SQLITE3`, and then runs a synchronous chat loop with SRUM query tools bound to the generated SQLite database.

Under `--BACKEND auto`, the agent first uses a complete API configuration from CLI arguments or environment variables. If no complete remote API configuration exists, it asks whether to use an existing API endpoint or set up a local LLM. Local setup asks for a local AI runtime directory, detects `llama-server` and a `.gguf` model there, starts llama.cpp, and can download a llama.cpp runtime plus a recommended GGUF model when they are missing and `--NO_PULL` is not set.

```bash
cd srum-dump
python srum-dump/srum-agent.py -i C:\Evidence\SRUDB.dat -o C:\Evidence\out -r C:\Evidence\SOFTWARE --NO_CONFIRM
```

Use an existing converted SQLite database without running conversion again:

```bash
python srum-dump/srum-agent.py --SQLITE_IN C:\Evidence\srum.sqlite3 --LOCAL_AI_DIR C:\Tools\local-ai
```

Use Ollama explicitly when it is already installed and you want that runtime:

```bash
python srum-dump/srum-agent.py --SQLITE_IN C:\Evidence\srum.sqlite3 --BACKEND ollama --MODEL llama3.2:3b
```

Useful agent options:

- `--SQLITE_OUT` writes conversion output to a specific path.
- `--SQLITE_IN` reuses an existing SRUM SQLite database.
- `--BACKEND auto|remote|ollama|llama_cpp` selects the inference runtime. `auto` asks whether to use an existing OpenAI-compatible API endpoint or set up a local LLM before database conversion starts.
- `--API_URL`, `--API_KEY`, and `--API_MODEL` configure an OpenAI-compatible remote or BYOK endpoint. If omitted, the agent checks `SRUM_AGENT_API_URL`, `AI_API_URL`, `OPENAI_BASE_URL`; `SRUM_AGENT_API_KEY`, `AI_API_KEY`, `OPENAI_API_KEY`; and `SRUM_AGENT_MODEL`, `AI_MODEL`, `OPENAI_MODEL`.
- `--MODEL` overrides the recommended model.
- `--NO_PULL` prevents automatic Ollama model pulls, llama.cpp runtime downloads, or Hugging Face GGUF downloads.
- `--LOCAL_AI_DIR` points to a directory containing or receiving a local llama.cpp runtime and GGUF model for auto local setup.
- `--LLAMA_CPP_URL` points to an OpenAI-compatible llama.cpp server for the `llama_cpp` backend.
- `--GGUF_MODEL_PATH` points to a local GGUF model file for optional `llama-server` startup.
- `--HF_GGUF_REPO` and `--HF_GGUF_FILE` download a GGUF model through Hugging Face Hub when `--NO_PULL` is not set.
- `--START_LLAMA_SERVER` starts `llama-server` with the resolved GGUF model instead of assuming a server is already running.

The agent exposes the existing in-process query helpers as LLM tools, including process, file, user-scoped process/file, user process/file summaries, network, Wi-Fi, PID, top CPU, and top network byte queries. Tool calls automatically inject the active SQLite path, so prompts do not need to mention database file locations. When a prompt does not specify a time range, the time-range tools default to all dates in the converted SRUM database. The agent is instructed to prefer these purpose-built tools over direct SQL; `query_database_read_only` is a fallback for schema exploration, date coverage, unusual columns, or questions without a direct helper.

## Dependencies
SRUM-DUMP relies on the following third-party libraries, which are installed automatically via `requirements.txt`:

### ESE Database Access:
- **[Dissect](https://github.com/fox-it/dissect)** – Used for structured parsing.
- **[pylibesedb](https://github.com/log2timeline/l2tbinaries)** – Precompiled binaries from the log2timeline project.

### XLS Output:
- **[XLSXWriter](https://pypi.org/project/XlsxWriter/)** – For generating Excel reports.

### Registry Access:
- **[python-registry](https://github.com/williballenthin/python-registry)** – To extract registry data.

### MCP Server:
- **[FastMCP](https://gofastmcp.com/)** – To expose the SQLite converter and SRUM query helpers as MCP tools.

### SRUM Agent:
- **[LangChain Core](https://python.langchain.com/)** – For message and tool-calling primitives.
- **[langchain-ollama](https://python.langchain.com/docs/integrations/chat/ollama/)** – Default Ollama chat backend.
- **[langchain-openai](https://python.langchain.com/docs/integrations/chat/openai/)** – OpenAI-compatible llama.cpp server client.
- **[huggingface_hub](https://huggingface.co/docs/huggingface_hub/)** – GGUF model download support for llama.cpp workflows.

## Contributing
I welcome contributions! Feel free to submit issues, feature requests, or pull requests. If you're adding features or fixing bugs, please ensure your code follows best practices and is tested before submission.

## License
This project is released under the [GNU GPL](LICENSE).





