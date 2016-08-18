# srum-dump

This program will create an excel spreadsheet containing forensics artifacts contained the SRUM (System Resource Utilization Manager) data base.

The program can be run with no input and it will prompt you for each of the needed arguments.   The program requires two inputs.  The first is an SRUM database.   The SRUM database is usually \Windows\system32\sru\SRUDB.dat.    The second is a XLSX template file that contains the names of the tables and fields that you want to extract from the SRUM database.   SRUM_TEMPLATE.xlsx is distributed with the program and it includes the fields that you will most likely be interested in.  If you want to add additinal XLS calculations or remove fields form the SRUM database you can make a copy of SRUM_TEMPLATE.xlsx and change that template file as needed.   The program will create a new XLSX file containing the fields specified inside the template.

The program will also optionally take a SOFTWARE registry hive.   The path for this files is typically \Windows\System32\config\SOFTWARE


Here is the usage statement.
 
usage: srum_dump.py [-h] [--ESE_INFILE ESE_INFILE]
                    [--XLSX_OUTFILE XLSX_OUTFILE]
                    [--XLSX_TEMPLATE XLSX_TEMPLATE] [--REG_HIVE REGHIVE]
                    [--quiet]

Given an SRUM database it will create an XLS spreadsheet with analysis of the
data in the database.

optional arguments:
  -h, --help            show this help message and exit
  --ESE_INFILE ESE_INFILE, -i ESE_INFILE
                        Specify the ESE (.dat) file to analyze. Provide a
                        valid path to the file.
  --XLSX_OUTFILE XLSX_OUTFILE, -o XLSX_OUTFILE
                        Full path to the XLS file that will be created.
  --XLSX_TEMPLATE XLSX_TEMPLATE, -t XLSX_TEMPLATE
                        The Excel Template that specifies what data to extract
                        from the srum database. You can create templates with
                        ese_template.py.
  --REG_HIVE REGHIVE, -r REGHIVE
                        If a registry hive is provided then the names of the
                        network profiles will be resolved.
  --quiet, -q           Supress unneeded output messages.



TEMPLATE FILE FORMAT:
A template file has multiple tabs.  Each tab is associated with a different table in the SRUM (or any ESE databaes).  On each tab in the template you put the following data:

Cell A1 = The name of the table inside the SRUM database
ROW  B  = The names of the fields (one per column) to extract from that table.  The field name #XLS_COLUMN# may also be included in this row if you want to have a calculated excel column as part of the output.  If the field name is #XLS_COLUMN# then the format field information will be placed in the output columm.  The string #ROW_NUM# can be used in the calculations to have a relative reference to the current row in the database.  Note the the formatting (fonts, borders, background fill, etc) of this row is applied to each row in the resulting output file.
ROW C  = Format commands to change that tell SRUM_DUMP how to interpret the data in that field.   Valid format commands include:
    OLE:[TimeDate Format String] Example: OLE:%Y-%m-%d %H:%M:%S This interprets the column data as a Windows OLE Date Time stamp
    FILE:[TimeDate Format String] Example: FILE:%Y-%m-%d %H:%M:%S This interprets the column data as a Windows File System Date Time stamp
    base16 (convert database field to hex)
    base2 (to binary)
    md5 (calucale a hash of the data)
    sha1 (calucale a hash of the data)
    sha256 (calucale a hash of the data)
ROW D  = Human Readable column names for the associated fields.  The contents of this row including its formatting will be come the columm headers in your resulting output xls file.

See the SRUM_TEMPLATE.XLSX for an example.  Check out ESE_ANALYST from http://github.com/MarkBaggett/ for more details.









