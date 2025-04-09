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

Valid colors are:
```"BLACK","WHITE","RED","GREEN","BLUE","YELLOW","CYAN","MAGENTA","GRAY","DARKRED","DARKGREEN","DARKBLUE","DARKYELLOW","DARKCYAN","DARKMAGENTA","DARKGRAY","LIGHTGRAY"```


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

## 5. Columns to Rename
This is a mapping of fields in the SRUM to friendly names that will appear as columns in the XLSX for better readability:
- `TimeStamp` → `SRUM Entry Creation (UTC)`
- `AppId` → `Application/Process`
- `ForegroundCycleTime` → `CPU time in Foreground`
- `ChargeLevel` → `Battery Level`

## 6. Skip Tables
Lists database tables that should be ignored during processing:
- Includes system tables such as `MSysObjects` and `SruDbIdMapTable`.

## 7. Known Tables
Maps internal table GUIDs to their corresponding functions.  Again this provides better readablility of the worksheets (tabs) in XLS and filenames for CSV files.

- `Application Timeline`: `{5C8CF1C7-7257-4F13-B223-970EF5939312}`
- `Network Data`: `{973F5D5C-1D90-4944-BE8E-24B94231A174}`
- `Energy Usage`: `{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}`

## 8. Columns to Translate
Defines how certain columns should be interpreted.  You generally do not want to make changes here unless you know what your doing. This controls how SRUM-DUMP treats a column when processing it.  

```
"columns_to_translate": {
        "TimeStamp": "OLE",
        "AppId": "APPID",
        "UserId": "SID"
}
```
Translation types that can be specified are:
 - OLE : Interpret at a UTC OLE Timestamp
 - APPID : Lookup the APPID in the SRUMID database
 - SID : Treat this as a user SID
 - FILE:%Y-%m-%d %H:%M:%S : Read this as a File Timestamp and put it into the strptime format specified
 - seconds : The column contans seconds, convert it into minutes
 - interface_type : Use the Interface Types specified in this same config to translate these
 - network_interface : Use the network_interface table specified in this same config to translate these 


## 9. Calculated Columns
Defines additional computed values that are added as new columns inthe specified table.  This allow you to dynamically create new columns on a table that contain XLSX formulas. For example, the following entry adds a new column called "Percentage Charge" to the "Energy Usage" worksheet and puts the formulat =I1/G1 in row number 1.  The value #ROW_NUM# will automatically be replaced with the current row number.

```
{
        "Energy Usage": {
            "Percentage Charge": "=I#ROW_NUM#/G#ROW_NUM#"
        }
    },
```
## 10. Interface Types
Maps numerical network interface types to their respective descriptions:
- `6` → `IF_TYPE_ETHERNET_CSMACD`
- `71` → `IF_TYPE_IEEE80211` (Wi-Fi)
- `24` → `IF_TYPE_SOFTWARE_LOOPBACK`

This configuration file plays a crucial role in processing the `SRUDB.dat` file, allowing for structured extraction, interpretation, and reporting of Windows system resource usage data.


## 11. SRUDbIdMapTable
This massive dictionary contains every string that was extracted from the activity found in srudb.dat file. While processing the tables in your srudb.dat the `AppID` and `UserID` values stored in the tables will be translated into these strings. If you know the name of malware or a particular process you can modify the strings in this table to make them stand out. String modifications here do not impact performance in the way that dirty word searches do. The entries are comprised of an App or UserId and the associated string. Do not change the keys (numbers) only change the strings.

- `3` → `!!svchost.exe!1972/12/14:16:22:50!1c364![LocalService] [nsi]`
- `4` → `S-1-5-19 (LocalService)`