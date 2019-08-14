SRUM-DUMP2 
```
To TEST:
Please Download both srum_dump2.exe and SRUM_TEMPLATE2.XLSX.
Place them in the same directory and double click srum_dump2.exe


To INSTALL:
git clone --branch srum_dump2 http://github.com/markbaggett/srum-dump
cd srum-dump
sudo -H python3 -m pip install -r requirements.txt


To RUN
python3 srum_dump2.py

```
    
```
Goals: 
Switch from Impacket ESE engine to libesedb-python
Add a GUI for windows Users
Add progress bars for output 
Be able to process ANY ese database
Dump all fields tables including those that are not defined in the templates
Allow templates to be used to specify field formats, column names, table names, SID lookups and other lookups.

Known Issues:
I have removed the capability to have XLS calculated fields and copy XLSX tabs. Considering dropping functionality from program. Users can easily add these fields after processing is completed.
```
