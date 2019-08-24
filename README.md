SRUM-DUMP2 
```
SRUM Dump extracts information from the System Resource Utilization Management Database. 

The SRUM is one of the best sources for applications that have run on your system in the last 30 days and is invaluable to your incident investigations! 

To use the tool you will need a copy of the SRUM (located in c:\windows\system32\sru\srudb.dat, but locked by the OS).
This tool also requires a SRUM_TEMPLATE that defines table and field names. You can optionally provide the SOFTWARE registry hive and the tool will tell you which wireless networks were in use by applications.
 
```



```
TO TEST THE TOOL:
Please Download both srum_dump2.exe and SRUM_TEMPLATE2.XLSX.
Place them in the same directory and double click srum_dump2.exe


To INSTALL:
Installation of the libesedb-pythom module can be hard on Windows, but its easy on Linux. Windows instructions are below.  On Linux..

git clone --branch srum_dump2 http://github.com/markbaggett/srum-dump
cd srum-dump
sudo -H python3 -m pip install -r requirements.txt


To RUN
python3 srum_dump2.py

```
    
```
Goals for the upgrade: 
Switch from Impacket ESE engine to libesedb-python
Add a GUI for windows Users
Add progress bars for output 
Be able to process ANY ese database, not just the SRUM
Dump all fields tables including those that are not defined in the templates
Allow templates to be used to specify field formats, column names, table names, SID lookups and other lookups.
LIVE System Aquisition when run as administrator

Known Issues: 
I have removed the capability to have XLS calculated fields and copy XLSX tabs. Considering dropping functionality from program. Users can easily add these fields after processing is completed.
```

```
Template Usage
The srum_template2.xlsx file is a way of defining lookups for fields found in ESE databases.
To understand its power try to dump your srum with BLANK_TEMPLATE.XLSX and compare the results.
You can provide friendsly names for tables and columns in the ESE tables.
The format row in the template tells srum to process fields and resolve their values. Some formats such as "lookup_SID" and "lookup_LUID" are hardcoded functions in srum_dump. You can suppliment the built in know SIDS with those form your investigation by adding them to the lookup-Known Sids sheet. 
ESE fields can be resolved dynamically when the format row contain "lookup-xlssheet-name".  You can Add XLS tabs containing lookup tables then add srum-dump will use it to resolve values in ese tables if their table has the name of the lookup table in format row (see lookup-ExampleNameNums) 
```

```
Windows Installation:
Installing libesedb-python on a windows system is hard because it requires a compiler be present and configured correctly. The matter is confused by the fact that Error messages give incorrect requirements about old versions of build tools. To compile from source follow these instructions.


1) Install Visual C++ build tools. This is not the same as the full visual studio install. Download the lates version from Microsoft.  Google "Visual C++ build tools". These links were accurate when I wrote this:

https://go.microsoft.com/fwlink/?LinkId=691126

https://download.microsoft.com/download/5/f/7/5f7acaeb-8363-451f-9425-68a90f98b238/visualcppbuildtools_full.exe

When prompted by the installer select ALL OF THE OPTIONAL PACKAGES. Do you really need all of them? No, but depending upon what your doing its hard to say what you will need. Just install them all.

2) Then install Python 3.  I installed Python 3.7.4.  Once again, select ALL the options including installing precompiled libraries, debug symbols, etc.  Again, you don't really need all of them for this specific project but you may for other projects so it nice to have a complete install for building libraries.

Next update pip and setuptools. For this project you will also need several additional modules.  Install them like this: 

pip install --upgrade pip
pip install --upgrade setuptools
pip install libesedb-python
pip install openpyxl
pip install python-registry
pip install pyinstaller
pip install pysimplegui
```

