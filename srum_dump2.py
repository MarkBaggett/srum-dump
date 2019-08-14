import pyesedb
from datetime import datetime,timedelta
import sys
import struct
import re
import openpyxl
from openpyxl.cell import WriteOnlyCell
from openpyxl.comments import Comment
from Registry import Registry
import argparse
import warnings
import hashlib
import random
import os
import codecs
import itertools
import PySimpleGUI as sg
import pathlib

def load_sids():
    known_sids = {}
    try:
        sid_sheet = template_wb.get_sheet_by_name("Known SIDS")
    except Exception as e:
        print("ERROR Reading the Known Sids from SRUM Template. Is this a SRUM_DUMP2 Template? {}".format(str(e)))
        return {}
    for eachrow in range(1,sid_sheet.max_row+1):
        sid = sid_sheet.cell(row = eachrow, column = 1).value
        acct = sid_sheet.cell(row = eachrow, column = 2).value
        known_sids[sid] = acct
    return known_sids

def lookup_sid(sid):
    if sid in known_sids:
        return "%s (%s)" % (sid, known_sids.get(sid,sid))
    return sid

def BinarySIDtoStringSID(sid):
  #Original form Source: https://github.com/google/grr/blob/master/grr/parsers/wmi_parser.py
  """Converts a binary SID to its string representation.
  https://msdn.microsoft.com/en-us/library/windows/desktop/aa379597.aspx
  The byte representation of an SID is as follows:
    Offset  Length  Description
    00      01      revision
    01      01      sub-authority count
    02      06      authority (big endian)
    08      04      subauthority #1 (little endian)
    0b      04      subauthority #2 (little endian)
    ...
  Args:
    sid: A byte array.
  Returns:
    SID in string form.
  Raises:
    ValueError: If the binary SID is malformed.
  """
  if not sid:
    return ""
  sid = codecs.decode(sid,"hex")
  str_sid_components = [sid[0]]
  # Now decode the 48-byte portion
  if len(sid) >= 8:
    subauthority_count = sid[1]
    identifier_authority = struct.unpack(">H", sid[2:4])[0]
    identifier_authority <<= 32
    identifier_authority |= struct.unpack(">L", sid[4:8])[0]
    str_sid_components.append(identifier_authority)
    start = 8
    for i in range(subauthority_count):
      authority = sid[start:start + 4]
      if not authority:
        break
      if len(authority) < 4:
        raise ValueError("In binary SID '%s', component %d has been truncated. "
                         "Expected 4 bytes, found %d: (%s)",
                         ",".join([str(ord(c)) for c in sid]), i,
                         len(authority), authority)
      str_sid_components.append(struct.unpack("<L", authority)[0])
      start += 4
      sid_str = "S-%s" % ("-".join([str(x) for x in str_sid_components]))
  return lookup_sid(sid_str)

def blob_to_string(binblob):
    chrblob = codecs.decode(binblob,"hex")
    try:
        if re.match(b'^(?:[^\x00]\x00)+\x00\x00$', chrblob):
            binblob = chrblob.decode("utf-16-le").strip("\x00")
        elif re.match(b'^(?:\x00[^\x00])+\x00\x00$', chrblob):
            binblob = chrblob.decode("utf-16-be").strip("\x00")
        else:
            binblob = chrblob.decode("latin1").strip("\x00")
    except:
        binblob = "" if not binblob else chrblob
    return binblob

def ole_timestamp(binblob):
    #converts a hex encoded OLE time stamp to a time string
    td,ts = str(struct.unpack("<d",binblob)[0]).split(".")
    dt = datetime(1899,12,30,0,0,0) + timedelta(days=int(td),seconds=86400 * float("0.{}".format(ts)))
    return dt
 
def file_timestamp(binblob):
    #converts a hex encoded windows file time stamp to a time string
    dt = datetime(1601,1,1,0,0,0) + timedelta(microseconds=binblob/10)
    return dt
 
def load_interfaces(reg_file):
    try:
        reg_handle = Registry.Registry(reg_file)
    except Exception as e:
        print("I could not open the specified SOFTWARE registry key. It is usually located in \Windows\system32\config.  This is an optional value.  If you cant find it just dont provide one.")
        print(("WARNING : ", str(e)))
        return {}
    try:
        int_keys = reg_handle.open('Microsoft\\WlanSvc\\Interfaces')
    except Exception as e:
        print("There doesn't appear to be any wireless interfaces in this registry file.")
        print(("WARNING : ", str(e)))
        return {}
    profile_lookup = {}
    for eachinterface in int_keys.subkeys():
        if len(eachinterface.subkeys())==0:
            continue
        for eachprofile in eachinterface.subkey("Profiles").subkeys():
            profileid = [x.value() for x in list(eachprofile.values()) if x.name()=="ProfileIndex"][0]
            metadata = list(eachprofile.subkey("MetaData").values())
            for eachvalue in metadata:
                if eachvalue.name()=="Channel Hints":
                    channelhintraw = eachvalue.value()
                    hintlength = struct.unpack("I", channelhintraw[0:4])[0]
                    name = channelhintraw[4:hintlength+4] 
                    profile_lookup[str(profileid)] = name.decode(encoding="latin1")
    return profile_lookup

def load_lookups(database):
    id_lookup = {}
    #Note columns  0 = Type, 1 = Index, 2 = Value
    lookup_table = database.get_table_by_name('SruDbIdMapTable')
    column_lookup = dict([(x.name,index) for index,x in enumerate(lookup_table.columns)])
    for rec_entry_num in range(lookup_table.number_of_records):
        bin_blob = smart_retrieve(lookup_table,rec_entry_num, column_lookup['IdBlob'])
        if smart_retrieve(lookup_table,rec_entry_num, column_lookup['IdType'])==3:
            bin_blob = BinarySIDtoStringSID(bin_blob)
        elif not bin_blob == "Empty":
            bin_blob = blob_to_string(bin_blob)
        id_lookup[smart_retrieve(lookup_table,rec_entry_num, column_lookup['IdIndex'])] = bin_blob
    return id_lookup

                
def smart_retrieve(ese_table, ese_record_num, column_number):
    ese_column_types = {0: 'NULL', 1: 'BOOLEAN', 2: 'INTEGER_8BIT_UNSIGNED', 3: 'INTEGER_16BIT_SIGNED', 4: 'INTEGER_32BIT_SIGNED', 5: 'CURRENCY', 6: 'FLOAT_32BIT', 7: 'DOUBLE_64BIT', 8: 'DATE_TIME', 9: 'BINARY_DATA', 10: 'TEXT', 11: 'LARGE_BINARY_DATA', 12: 'LARGE_TEXT', 13: 'SUPER_LARGE_VALUE', 14: 'INETEGER_32BIT_UNSIGNED', 15: 'INTEGER_64BIT_SIGNED', 16: 'GUID', 17: 'INTEGER_16BIT_UNSIGNED'}
    rec = ese_table.get_record(ese_record_num)
    col_type = rec.get_column_type(column_number)
    col_data = rec.get_value_data(column_number)
    #print "rec:%s  col:%s type:%s %s" % (ese_record_num, column_number, col_type, ese_column_types[col_type])
    if col_type == pyesedb.column_types.BINARY_DATA:
        col_data = "" if not col_data else codecs.encode(col_data,"HEX")
    elif col_type == pyesedb.column_types.BOOLEAN:
        col_data = struct.unpack('?',col_data)[0]
    elif col_type == pyesedb.column_types.CURRENCY:
        pass
    elif col_type == pyesedb.column_types.DATE_TIME:
        col_data = ole_timestamp(col_data)
    elif col_type == pyesedb.column_types.DOUBLE_64BIT:
        col_data = 0 if not col_data else struct.unpack('d',col_data)[0]
    elif col_type == pyesedb.column_types.FLOAT_32BIT:
        col_data = 0.0 if not col_data else struct.unpack('f',col_data)[0]
    elif col_type == pyesedb.column_types.GUID:
        col_data = str(uuid.UUID(col_data.encode('hex')))    
    elif col_type == pyesedb.column_types.INTEGER_16BIT_SIGNED:
        col_data = 0 if not col_data else struct.unpack('h',col_data)[0]
    elif col_type == pyesedb.column_types.INTEGER_16BIT_UNSIGNED:
        col_data = 0 if not col_data else struct.unpack('H',col_data)[0]
    elif col_type == pyesedb.column_types.INTEGER_32BIT_SIGNED:
        col_data =  0 if not col_data else struct.unpack('i',col_data)[0]
    elif col_type == pyesedb.column_types.INTEGER_32BIT_UNSIGNED:
        col_data = 0 if not col_data else struct.unpack('I',col_data)[0]
    elif col_type == pyesedb.column_types.INTEGER_64BIT_SIGNED:
        col_data = 0 if not col_data else struct.unpack('q',col_data)[0]
    elif col_type == pyesedb.column_types.INTEGER_8BIT_UNSIGNED:
        col_data = 0 if not col_data else struct.unpack('B',col_data)[0]
    elif col_type == pyesedb.column_types.LARGE_BINARY_DATA:
        col_data = "" if not col_data else codecs.encode(col_data,"HEX")
    elif col_type == pyesedb.column_types.LARGE_TEXT:
        col_data = blob_to_string(col_data)
    elif col_type == pyesedb.column_types.NULL:
        pass
    elif col_type == pyesedb.column_types.SUPER_LARGE_VALUE:
        col_data = "" if not col_data else codec.encode(col_data,"HEX")
    elif col_type == pyesedb.column_types.TEXT:
        col_data = blob_to_string(col_data)   
    else:
        col_data = blob_to_string(col_data)    
    if col_data==None:
        col_data = "Empty"
    return col_data

def format_output(val,eachformat, eachstyle):
    "Returns a excel cell with the data formated as specified"
    new_cell = WriteOnlyCell(xls_sheet, value = "init")
    new_cell.style = eachstyle
    if val==None:
        val="None"
    elif eachformat in [None, "OLE"]:
        pass
    elif eachformat.startswith("FILE:"):
        pass
    elif eachformat=="FILE":
        val = file_timestamp(val)
        new_cell.number_format = 'YYYY MMM DD'
    elif eachformat.startswith("FILE:"):
        val = file_timestamp(val)
        val = val.strftime(eachformat[5:])
    elif eachformat.lower() == "lookup_id":
        val = id_table.get(val, "No match in srum lookup table for %s" % (val))
    elif eachformat.lower() == "lookup_luid":
        val = lookup_luid(val)
    elif eachformat.lower() == "lookup_sid":
        val = "%s (%s)" % (val, lookup_sid(val))
    elif eachformat.lower() == "seconds":
        val = val/86400.0
        new_cell.number_format = 'dd hh:mm:ss'
    elif eachformat.lower() == "md5":
        val = hashlib.md5(str(val)).hexdigest()
    elif eachformat.lower() == "sha1":
        val = hashlib.sha1(str(val)).hexdigest()
    elif eachformat.lower() == "sha256":
        val = hashlib.sha256(str(val)).hexdigest()
    elif eachformat.lower() == "base16":
        if type(val)==int:
            val = hex(val)
        else:
            val = format(val,"08x")
    elif eachformat.lower() == "base2":
        if type(val)==int:
            val = format(val,"032b")
        else:
            try:
                val = int(str(val),2)
            except :
                val = val
                new_cell.comment = Comment("Warning: Unable to convert value %s to binary." % (val),"srum_dump")
    elif eachformat.lower() == "interface_id" and options.reghive:
        val = interface_table.get(str(val),"")
    elif eachformat.lower() == "interface_id" and not options.reghive:
        val = val
        new_cell.comment = Comment("WARNING: Ignoring interface_id format command because the --REG_HIVE was not specified.", "srum_dump")
    else:
        val = val
        new_cell.comment =  Comment("WARNING: I'm not sure what to do with the format command %s.  It was ignored." % (eachformat), "srum_dump")  
    new_cell.value = val  
    return new_cell

def load_luid():
    known_sids = {}
    try:
        sid_sheet = template_wb.get_sheet_by_name("LUID Interfaces")
    except Exception as e:
        print("ERROR Reading the Known Sids from SRUM Template. Is this a SRUM_DUMP2 Template? {}".format(str(e)))
        return {}
    for eachrow in range(1,sid_sheet.max_row+1):
        sid = sid_sheet.cell(row = eachrow, column = 1).value
        acct = sid_sheet.cell(row = eachrow, column = 2).value
        known_sids[sid] = acct
    return known_sids
    
def lookup_luid(luidval):
    inttype = struct.unpack(">H6B", codecs.decode(format(luidval,'016x'),'hex'))[0]
    return LUID_interface_types.get(inttype,'Unknown Interface type')

def load_templates(path_to_template):
    templates = {}    
    sheets = template_wb.get_sheet_names()
    for each_sheet in sheets:
        #open the first sheet in the template
        template_sheet = template_wb.get_sheet_by_name(each_sheet)
        #retieve the name of the ESE table to populate the sheet with from A1
        ese_template_table = template_sheet.cell(row=1,column=1).value
        #retrieve the names of the ESE table columns and cell styles from row 2 and format commands from row 3 
        template_field = {}
        #Read the first Row B & C in the template into lists so we know what data we are to extract
        for eachcolumn in range(1,template_sheet.max_column+1):
            field_name = template_sheet.cell(row = 2, column = eachcolumn).value
            if field_name == None:
                break
            template_style = template_sheet.cell(row = 4, column = eachcolumn).style
            template_format = template_sheet.cell(row = 3, column = eachcolumn).value
            template_value = template_sheet.cell(row = 4, column = eachcolumn ).value
            template_field[field_name] = (template_style,template_format,template_value)
        templates[ese_template_table] = (each_sheet, template_field)
    return templates    

def process_srum(ese_db, skip_tables = ['MSysObjects', 'MSysObjectsShadow', 'MSysObjids', 'MSysLocales','SruDbIdMapTable']):
    global xls_sheet
    for table_num in range(ese_db.number_of_tables):
        ese_table = ese_db.get_table(table_num)
        if ese_table.name in skip_tables:
            continue

        if ese_table.name in templates:
            tname,tfields = templates.get(ese_table.name)
        else:
            tname = ese_table.name

        if not options.quiet:
            print("Now dumping table {} containing {} rows".format(tname, ese_table.number_of_records))
            print("While you wait, did you know ...\n {} \n".format(next(ads)))

        xls_sheet = target_wb.create_sheet(title=tname)

        header_row = [x.name for x in ese_table.columns]
        if ese_table.name in templates:
            tname,tfields = templates.get(ese_table.name)
            header_row = []
            for eachcol in ese_table.columns:
                if eachcol.name in tfields:
                    cell_style,cell_format,cell_value = tfields.get(eachcol.name)
                    new_cell = WriteOnlyCell(xls_sheet, value=cell_value)
                    new_cell.style = cell_style
                    header_row.append( new_cell )
                else:
                    header_row.append(WriteOnlyCell(xls_sheet, value=eachcol.name))
        xls_sheet.append(header_row)
    
        column_names = [x.name for x in ese_table.columns]
        for row_num in range(ese_table.number_of_records):
            try:
                ese_row = ese_table.get_record(row_num)
            except Exception as e:
                print("Skipping corrupt row in the %s table.  The last good row was %s." % (each_sheet, row_num))
                continue
            if ese_row == None:
                continue
            #The row is retrieved now use the template to figure out which ones you want and format them
            xls_row = []
            for col_num in range(ese_table.number_of_columns):
                val = smart_retrieve(ese_table,row_num, col_num)
                if val=="Error":
                    val = "WARNING: Invalid Column Name {}".format(column_name[col_num])
                elif val==None:
                    val="None"  
                elif ese_table.name in templates:
                    tname,tfields = templates.get(ese_table.name) 
                    if column_names[col_num] in tfields:
                        cstyle,cformat,cval = tfields.get(column_names[col_num])
                        val = format_output(val, cformat, cstyle)              
                #print dir(new_cell.style.font)
                xls_row.append(val)
            xls_sheet.append(xls_row)
    
parser = argparse.ArgumentParser(description="Given an SRUM database it will create an XLS spreadsheet with analysis of the data in the database.")
parser.add_argument("--SRUM_INFILE","-i", help ="Specify the ESE (.dat) file to analyze. Provide a valid path to the file.")
parser.add_argument("--XLSX_OUTFILE", "-o", default="SRUM_DUMP_OUTPUT.xlsx", help="Full path to the XLS file that will be created.")
parser.add_argument("--XLSX_TEMPLATE" ,"-t", help = "The Excel Template that specifies what data to extract from the srum database. You can create templates with ese_template.py.")
parser.add_argument("--REG_HIVE", "-r", dest="reghive", help = "If a registry hive is provided then the names of the network profiles will be resolved.")
parser.add_argument("--quiet", "-q", help = "Supress unneeded output messages.",action="store_true")
options = parser.parse_args()

ads = itertools.cycle(["Did you know SANS Automating Infosec with Python SEC573 teaches you to develop Forensics and Incident Response tools?.",
       "To learn how SRUM and other artifacts can enhance your forensics investigations check out SANS Windows Forensic Analysis FOR500",
       "This program uses the function BinarySIDtoStringSID from the GRR code base to convert binary data into a user SID and relies heavily on the CoreSecurity Impacket ESE module. This works because of them.  Check them out!",
       "Yogesh Khatri's paper at https://files.sans.org/summit/Digital_Forensics_and_Incident_Response_Summit_2015/PDFs/Windows8SRUMForensicsYogeshKhatri.pdf was essential in the creation of this tool.",
       "By modifying the template file you have control of what ends up in the analyzed results.  Try creating an alternate template and passing it with the --XLSX_TEMPLATE option.",
       "This program was written by Twitter:@markbaggett and @donaldjwilliam5 because @ovie said so.",
       ])


if not options.SRUM_INFILE:
    srum_path = ""
    if os.path.exists("SRUDB.DAT"):
        srum_path = os.path.join(os.getcwd(),"SRUDB.DAT")
    temp_path = ""
    if os.path.exists("SRUM_TEMPLATE.XLSX"):
        temp_path = os.path.join(os.getcwd(),"SRUM_TEMPLATE2.XLSX")
    reg_path = ""
    if os.path.exists("SOFTWARE"):
        reg_path = os.path.join(os.getcwd(),"SOFTWARE")

    layout = [[sg.Text('REQUIRED: Path to SRUDB.DAT')],
    [sg.Input(srum_path,key="_SRUMPATH_"), sg.FileBrowse(target="_SRUMPATH_")], 
    [sg.Text('REQUIRED: Output folder for srum_dump.xlsx')],
    [sg.Input(os.getcwd(),key='_OUTDIR_', enable_events=True), sg.FolderBrowse(target='_OUTDIR_')],
    [sg.Text('REQUIRED: Path to SRUM_DUMP TEMPLATE')],
    [sg.Input(temp_path,key="_TEMPATH_"), sg.FileBrowse(target="_TEMPATH_")],
    [sg.Text('OPTIONAL: Path to registry SOFTWARE hive')],
    [sg.Input(key="_REGPATH_"), sg.FileBrowse(target="_REGPATH_")],
    [sg.Text("")],
    [sg.OK(), sg.Cancel()]] 
    
    # Create the Window
    window = sg.Window('SRUM_DUMP', layout)
    # Event Loop to process "events"
    while True:             
        event, values = window.Read()
        print(event,values)
        if event in (None, 'Cancel'):
            sys.exit(0)
        if event in (None, 'OK'):
            if not os.path.exists(pathlib.Path(values.get("_SRUMPATH_"))):
                sg.Popup("SRUM DATABASE NOT FOUND.")
                continue
            if not os.path.exists(pathlib.Path(values.get("_OUTDIR_"))):
                sg.Popup("OUTPUT DIR NOT FOUND.")
                continue            
            if not os.path.exists(pathlib.Path(values.get("_TEMPATH_"))):
                sg.Popup("SRUM TEMPLATE NOT FOUND.")
                continue
            if values.get("_REGPATH_") and not os.path.exists(pathlib.Path(values.get("_REGPATH_"))):
                sg.Popup("REGISTRY File not found. (Leave field empty for None.)")
                continue
            break

    window.Close()
    options.SRUM_INFILE = str(pathlib.Path(values.get("_SRUMPATH_")))
    #input(r"What is the path to the SRUDB.DAT file? (Ex: \image-mount-point\Windows\system32\sru\srudb.dat) : ")
    options.XLSX_OUTFILE = str(pathlib.Path(values.get("_OUTDIR_")) / "srum_out.xlsx")
    #input(r"What is my output file name (Press enter for the default SRUM_DUMP_OUTPUT.xlsx) (Ex: \users\me\Desktop\resultx.xlsx) : ")
    options.XLSX_TEMPLATE = str(pathlib.Path(values.get("_TEMPATH_")))
    #input("What XLS Template should I use? (Press enter for the default SRUM_TEMPLATE.XLSX) : ")
    options.reghive = str(pathlib.Path(values.get("_REGPATH_")))
    if options.reghive == ".":
        options.reghive = ""
    #input("What is the full path of the SOFTWARE registry hive? Usually \image-mount-point\Windows\System32\config\SOFTWARE (or press enter to skip Network resolution) : ")
else:
    if not options.XLSX_TEMPLATE:
        options.XLSX_TEMPLATE = "SRUM_TEMPLATE2.xlsx"

    if not options.XLSX_OUTFILE:
        options.XLSX_OUTFILE = "SRUM_DUMP_OUTPUT.xlsx"

    if not os.path.exists(options.SRUM_INFILE):
        print("ESE File Not found: "+options.SRUM_INFILE)
        sys.exit(1)

    if not os.path.exists(options.XLSX_TEMPLATE):
        print("Template File Not found: "+options.XLSX_TEMPLATE)
        sys.exit(1)

    if options.reghive and not os.path.exists(options.reghive):
        print("Registry File Not found: "+options.reghive)
        sys.exit(1)



if options.reghive:
    interface_table = load_interfaces(options.reghive)

try:
    warnings.simplefilter("ignore")
    ese_db = pyesedb.file()
    ese_db.open(options.SRUM_INFILE)
    #ese_db = ese.ESENT_DB(options.SRUM_INFILE)
except Exception as e:
    print("I could not open the specified SRUM file. Check your path and file name.")
    print("Error : ", str(e))
    sys.exit(1) 

try:
    template_wb = openpyxl.load_workbook(filename=options.XLSX_TEMPLATE)
except Exception as e:
    print("I could not open the specified template file %s. Check your path and file name." % (options.XLSX_TEMPLATE))
    print("Error : ", str(e))
    sys.exit(1)


xls_sheet =  ""
templates = load_templates(template_wb)
known_sids = load_sids()
LUID_interface_types = load_luid()
id_table = load_lookups(ese_db)
target_wb = openpyxl.Workbook()

"""
layout = [      
    [sg.Output(size=(88, 20))],      
    [sg.Text('While you wait...', size=(15, 2))] , 
    [sg.OK()]    
        ]      
    
# Create the Window
window = sg.Window('Processing ....', layout)
# Event Loop to process "events"
while True:             
    event, values = window.Read(timeout=10)
    
    if event in (None, 'OK'):
        if not os.path.exists(pathlib.Path(values.get("_SRUMPATH_"))):
            sg.Popup("SRUM DATABASE NOT FOUND.")
            continue
"""

process_srum(ese_db)

    
firstsheet=target_wb.get_sheet_by_name("Sheet")
target_wb.remove_sheet(firstsheet)

try:
    target_wb.save(options.XLSX_OUTFILE)
except Exception as e:
    print("I was unable to write the output file.  Do you have an old version open?  If not this is probably a path or permissions issue.")
    print("Error : ", str(e))



