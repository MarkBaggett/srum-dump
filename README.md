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

