# Configuration File Explanation: srum_dump_config.json

This document explains the structure and purpose of the different sections within the `srum_dump_config.json` configuration file. This file is used to process and extract information from the `SRUDB.dat` database, which is a part of the Windows System Resource Usage Monitor (SRUM).

## 1. Defaults
This section defines the main file paths and processing parameters:
- **SRUM_INFILE**: The path to the `SRUDB.dat` database file, which stores system resource usage data.
- **OUT_DIR**: The directory where the extracted data and reports will be saved.
- **REG_HIVE**: The path to the Windows Registry hive (`SOFTWARE`), which may contain additional context for interpretation.
- **ESE_ENGINE**: Specifies the database engine used to process `SRUDB.dat` (e.g., `dissect`).
- **OUTPUT_FORMAT**: Defines the format for output files (e.g., `xls` for Excel format).

## 2. Dirty Words
This section specifies terms that are flagged during analysis.  Any string you put here that is a substring of a process, username or interface will be changed to the specified color.
- Keywords such as `cmd.exe` are marked with an associated color (e.g., `RED`).
- Used to highlight significant terms that might indicate anomalies or security concerns.

WARNING: Dirty words significantly impact processing speed and result in longer waits for results.

The value associated with each dirty word should be a valid style name defined in the `output_xlsx.py` module. These styles determine the formatting applied to cells containing the dirty word. See the `column_markups` section below for details on available styles. Example:
```json
"dirty_words": {
    "cmd.exe": "highlight-red",
    "powershell.exe": "highlight-yellow",
    "suspicious_process": "general-red-bold"
}
```

## 3. Network Interfaces
This information is extracted from your SOFTWARE registry hive. It is blank if no SOFTWARE hive is provided. These entries contain a Network Identifier and a friendly name to translate it to. You can enhance your investigations by changing the names so the network in question stands out. Changing network names does not impact performance in the way that dirty words do.

```
 "network_interfaces": {
        "268435498": "MarriottBonvoy",
        "268435490": "SEC573",
        "268435461": "BSidesAugusta-2022",
        "268435471": "MarriottBonvoy_Guest",
    },
```

## 4. Known SIDs
Maps Windows Security Identifiers (SIDs) to user-friendly names. This section contains both the well known SIDs and those extracted from the SOFTWARE hive if one was provided. You can change the names to make suspect users easier to identify. For investigations in an enterprise environment include the SIDs of all active directory users here.

- Includes well-known SIDs such as `S-1-5-32-544` (Administrators) and `S-1-5-11` (Authenticated Users).
- SIDs extracted from SOFTWARE: `S-1-5-21-829147445-693982232-3163077201-1001`.

## 5. Skip Tables
Lists database tables that should be ignored during processing:
- Includes system tables such as `MSysObjects` and `SruDbIdMapTable`.

## 6. Known Tables
Maps internal table GUIDs to their corresponding functions.  Again this provides better readablility of the worksheets (tabs) in XLS and filenames for CSV files.

- `Application Timeline`: `{5C8CF1C7-7257-4F13-B223-970EF5939312}`
- `Network Data`: `{973F5D5C-1D90-4944-BE8E-24B94231A174}`
- `Energy Usage`: `{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}`

## 7. Column Markups

This section consolidates column configuration. It allows for defining column properties globally (under `"All Tables"`) or specifically for individual tables (identified by their friendly name from the `known_tables` section). Table-specific settings override the "All Tables" settings.

Each column entry within `column_markups` can have the following attributes:

- **`friendly_name`**: (String) Sets the display name for the column header in the output.
- **`translate`**: (String) Specifies how the raw column data should be interpreted or translated. Valid translation types are:
    - `OLE`: Interpret as a UTC OLE Timestamp (results in a datetime object).
    - `APPID`: Look up the value in the `SRUDbIdMapTable` section.
    - `SID`: Interpret as a Windows Security Identifier (SID) and look up in `known_sids`.
    - `FILE:%Y-%m-%d %H:%M:%S`: Interpret as a Windows FILETIME timestamp and format using the provided `strftime` string (results in a datetime object).
    - `seconds`: Interpret the value as a number of seconds and convert it to an Excel time value (fraction of a day).
    - `interface_types`: Look up the value in the `interface_types` section.
    - `network_interface`: Look up the value in the `network_interfaces` section.
- **`formula`**: (String) Defines an Excel formula for a calculated column. The placeholder `#ROW_NUM#` will be replaced with the current row number during processing. Formulas are added as new columns to the specified table (replaces `calculated_columns`).
- **`style`**: (String) Applies specific cell formatting using predefined styles. See "Style Options" below.
- **`width`**: (String representing an Integer) Sets a specific column width in the Excel output.

**Example Structure:**

```json
"column_markups": {
    "All Tables": {
        "TimeStamp": {
            "friendly_name": "SRUM Entry Creation (UTC)",
            "translate": "OLE",
            "style": "datetime" // Apply datetime cell format
        },
        "AppId": {
            "friendly_name": "Application/Process",
            "translate": "APPID",
            "width": "100"
        },
        "UserId": {
            "friendly_name": "User Information",
            "translate": "SID",
            "width": "60"
        },
        // ... other common columns
    },
    "Energy Usage": { // Table-specific overrides/additions
        "ChargeLevel": { // Override style for an existing column
             "style": "percentage-blue"
        },
        "Percentage Charge": { // Add a calculated column specific to this table
            "friendly_name": "Charge Percentage",
            "formula": "=I#ROW_NUM#/G#ROW_NUM#",
            "style": "percentage-green-bold" // Style for the calculated column
        }
    }
    // ... other table-specific sections
}
```

**Style Options (`style` attribute):**

The `style` attribute applies formatting defined in `output_xlsx.py`. Available styles include:

*   **Basic Number Formats:** Apply standard Excel number formats.
    *   `general`: Default format.
    *   `text`: Treat content as text.
    *   `number`: Format as number with 2 decimal places (e.g., `1,234.56`).
    *   `integer`: Format as integer (e.g., `1,234`).
    *   `percentage`: Format as percentage with 4 decimal places (e.g., `12.3456%`).
    *   `date`: Format as `mm/dd/yyyy`.
    *   `time`: Format as `hh:mm:ss`.
    *   `datetime`: Format as `mm/dd/yyyy hh:mm`.
*   **Colored Text:** Combine a basic format with a font color.
    *   Syntax: `[basic_format]-[color]` (e.g., `number-red`, `date-blue`).
    *   Available Colors: `red`, `blue`, `yellow`, `green`.
*   **Bold Colored Text:** Make colored text bold.
    *   Syntax: `[basic_format]-[color]-bold` (e.g., `integer-green-bold`).
*   **Highlight Styles:** Apply background color and contrasting font color. Uses the `General` number format.
    *   Syntax: `highlight-[background_color]` (e.g., `highlight-red`, `highlight-yellow`).
    *   Available Background Colors: `red`, `yellow`, `blue`, `green`, `purple`.

## 8. Interface Types
Maps numerical network interface types to their respective descriptions:
- `6` → `IF_TYPE_ETHERNET_CSMACD`
- `71` → `IF_TYPE_IEEE80211` (Wi-Fi)
- `24` → `IF_TYPE_SOFTWARE_LOOPBACK`

This configuration file plays a crucial role in processing the `SRUDB.dat` file, allowing for structured extraction, interpretation, and reporting of Windows system resource usage data.


## 9. SRUDbIdMapTable
This massive dictionary contains every string that was extracted from the activity found in srudb.dat file. While processing the tables in your srudb.dat the `AppID` and `UserID` values stored in the tables will be translated into these strings. If you know the name of malware or a particular process you can modify the strings in this table to make them stand out. String modifications here do not impact performance in the way that dirty word searches do. The entries are comprised of an App or UserId and the associated string. Do not change the keys (numbers) only change the strings.

- `3` → `!!svchost.exe!1972/12/14:16:22:50!1c364![LocalService] [nsi]`
- `4` → `S-1-5-19 (LocalService)`

---

