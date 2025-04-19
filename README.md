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

## Dependencies
SRUM-DUMP relies on the following third-party libraries, which are installed automatically via `requirements.txt`:

### ESE Database Access:
- **[Dissect](https://github.com/fox-it/dissect)** – Used for structured parsing.
- **[pylibesedb](https://github.com/log2timeline/l2tbinaries)** – Precompiled binaries from the log2timeline project.

### XLS Output:
- **[XLSXWriter](https://pypi.org/project/XlsxWriter/)** – For generating Excel reports.

### Registry Access:
- **[python-registry](https://github.com/williballenthin/python-registry)** – To extract registry data.

## Contributing
I welcome contributions! Feel free to submit issues, feature requests, or pull requests. If you're adding features or fixing bugs, please ensure your code follows best practices and is tested before submission.

## License
This project is released under the [GNU GPL](LICENSE).





