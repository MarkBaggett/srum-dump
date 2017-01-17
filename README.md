# srum-dump

parse forensics artifacts contained the SRUM (System Resource Utilization Manager) database.


## usage

```
pip install -r requirements.txt
python srum_dump.py SRUM.dat
```

## example output

This tool outputs json documents, one per entry in the database.
The only required keys will be `table_guid` and `table_purpose`.
The remaining keys depend on the schema of the SRUM database, though this is typically constant.
Here's an example of one entry formatted by this tool:

```
{
  "table_name": "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}",
  "table_purpose": "Application Resource Usage",
  "AppId": "\\Device\\HarddiskVolume2\\Program Files\\Windows Defender\\NisSrv.exe",
  "TimeStamp": "2017-01-11T21:22:00Z",
  "ForegroundBytesRead": 0,
  "ForegroundNumberOfFlushes": 0,
  "UserId": "S-1-5-19 ( NT Authority)",
  "ForegroundNumReadOperations": 0,
  "ForegroundNumWriteOperations": 21,
  "ForegroundBytesWritten": 86016,
  "ForegroundContextSwitches": 1165,
  "ForegroundCycleTime": 1732512255,
  "BackgroundBytesRead": 0,
  "BackgroundBytesWritten": 0,
  "BackgroundNumWriteOperations": 0,
  "BackgroundNumberOfFlushes": 0,
  "BackgroundCycleTime": 0,
  "BackgroundContextSwitches": 0,
  "BackgroundNumReadOperations": 0
  "FaceTime": 17999840000,
  "AutoIncId": 1645,
}
```


## credits

This tool is based on the script by Mark Baggett found here:
https://github.com/MarkBaggett/srum-dump

