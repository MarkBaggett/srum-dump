# SRUM-DUMP (Version 3)

SRUM-DUMP extracts data from the System Resource Utilization Management (SRUM) database and generates an Excel spreadsheet. This tool is invaluable for forensic investigations, as SRUM maintains records of applications that have run on a system within the last 30 days.

## Features
- Extracts and analyzes data from `SRUDB.DAT`
- Generates an Excel report for easy analysis
- Supports additional enrichment using the SOFTWARE registry hive
- Provides a configuration file for fine-tuned extraction

## Download and Installation
A prebuilt version of SRUM-DUMP is available for download in the [Releases](https://github.com/MarkBaggett/srum-dump/releases) section.

Alternatively, you can clone and run the project from the source code.

## Running SRUM-DUMP
### Using the Prebuilt Tool

![SRUM-DUMP GUI](srum-dump-use.gif)

1. **Launch the tool**: Run the executable.
2. **Select an output directory**: Choose an empty directory where the working files and results will be stored.
3. **Select the SRUDB.DAT file**:
   - This is a required file.
   - If selecting `C:\Windows\System32\sru\srudb.dat` on a live system, administrative privileges are required.
   - Windows 11 hosts may have issues extracting SRUM data, but Windows 11 virtual machines work fine. See the [Issues](https://github.com/MarkBaggett/srum-dump/issues) section for more details.
4. **(Optional) Select the SOFTWARE registry hive**:
   - This file provides useful additional context.
   - If unavailable, leave this field blank.
5. **Confirm Configuration**:
   - The tool will analyze your SOFTWARE hive and generate a configuration file.
   - Edit the configuration file to fine-tune the analysis (see [configuration_file.md](configuration_file.md)).
   - Click "CONFIRM" to proceed.
6. **Run the analysis**:
   - The tool will process the data and generate the output.
   - A progress dialog will appear, and the "Close" button will be disabled until the process completes.

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
- **[OpenPyXL](https://openpyxl.readthedocs.io/)** – For generating Excel reports.

### Registry Access:
- **[python-registry](https://github.com/williballenthin/python-registry)** – To extract registry data.

## Contributing
We welcome contributions! Feel free to submit issues, feature requests, or pull requests. If you're adding features or fixing bugs, please ensure your code follows best practices and is tested before submission.

## License
This project is released under the [MIT License](LICENSE).





