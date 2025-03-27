import argparse
import os
import pathlib
import warnings
import sys
import ctypes
import time
import struct
import codecs
import datetime

import copy_locked
import helpers

# Import the desired UI and DB modules
from ui_tk import get_user_input, get_input_wizard, error_message_box, message_box, ProgressWindow

#from db_dissect import srum_database
from config_manager import ConfigManager
from output_xlsx import OutputXLSX



parser = argparse.ArgumentParser(description="Given an SRUM database it will create an XLS spreadsheet or CSV with analysis of the data in the database.")
parser.add_argument("--SRUM_INFILE", "-i", help="Specify the ESE (.dat) file to analyze. Provide a valid path to the file.")
parser.add_argument("--OUT_DIR", "-o", help="Full path to a working output directory.")
parser.add_argument("--REG_HIVE", "-r", help="If SOFTWARE registry hive is provided then the names of the network profiles will be resolved.")
parser.add_argument("--ESE_ENGINE", "-e", choices=['pyesedb', 'dissect'], default='dissect', help="Corrupt file? Try a different engine to see if it does better. Options are pyesedb or dissect")
parser.add_argument("--OUTPUT_FORMAT", "-f", choices=['xls', 'csv'], default='xls', help="Specify the output format. Options are xls or csv. Default is xls.")
options = parser.parse_args()


if not options.OUT_DIR:
    get_input_wizard(options)  #Get paths with wizard
    config_path = pathlib.Path(options.OUT_DIR).joinpath("srum_dump_config.json")
    config = ConfigManager(config_path)
    if not config_path.is_file():
        config.set_config("defaults", vars(options))
        config.set_config("dirty_words", helpers.dirty_words)
        config.set_config("network_interfaces", {})
        config.set_config("known_sids", helpers.known_sids)
        config.set_config("columns_to_rename", helpers.columns_to_rename)
        config.set_config("skip_tables", helpers.skip_tables)
        config.set_config("known_tables", helpers.known_tables)
        config.set_config("columns_to_translate", helpers.columns_to_translate)
        config.set_config("calculated_columns", helpers.calculated_columns)
        config.set_config("interface_types", helpers.interface_types)
        config.save()
else:
    config_path = pathlib.Path(options.OUT_DIR).joinpath("srum_dump_config.json")
    config = ConfigManager(config_path)
    if not config_path.is_file():
        error_message_box("Error", "Configuration file not found. Please run the program without the OUT_DIR option first.")
        sys.exit(1)
    options = argparse.Namespace(**config.get_config("defaults"))
    options.OUT_DIR = str(config_path.parent)


if options.SRUM_INFILE:
    # Check if live system
    if pathlib.Path(os.environ['SystemRoot']).resolve() in pathlib.Path(options.SRUM_INFILE).parents:
        if ctypes.windll.shell32.IsUserAnAdmin() != 1:
            error_message_box("Error", "The file you selected is locked by the operating system. Please run this program as an administrator or select a different file.")   
            sys.exit(1)
        else:
            success = copy_locked.copy_locked_files(options.OUT_DIR)
            options.SRUM_INFILE = str(pathlib.Path(options.OUT_DIR).joinpath("SRUDB.dat"))
            options.REG_HIVE =  str(pathlib.Path(options.OUT_DIR).joinpath("SOFTWARE"))
            options.OUT_DIR = str(pathlib.Path(options.OUT_DIR))
            config.set_config("defaults", vars(options))
            config.save()
            if not success:
                sys.exit(1)



#If a registry hive is provided extract SIDS and network profiles and put it in the config file
if options.REG_HIVE:
    network_interfaces = helpers.load_interfaces(options.REG_HIVE)
    known_sids = config.get_config("known_sids")
    registry_sids = helpers.load_registry_sids(options.REG_HIVE)
    if network_interfaces:
        config.set_config("network_interfaces", network_interfaces)
        config.save()
    if registry_sids:
        known_sids.update(registry_sids)
        config.set_config("known_sids", known_sids)
        config.save()
    
#Let User confirm the settings and paths.  Then save for reuse next time
get_user_input(options)

#Use the config they selected in the dialog box for processing.
config.load()

#Select ESE engine
if options.ESE_ENGINE == "pyesedb":
    from db_ese import srum_database
else:
    from db_dissect import srum_database


#Select Output Engine and create output object
if options.OUTPUT_FORMAT == "xls":
    from output_xlsx import OutputXLSX
    output = OutputXLSX()
else:
    from output_csv import OutputCSV
    output = OutputCSV()

#Open database using specified engine
try:
    warnings.simplefilter("ignore")
    ese_db = srum_database(options.SRUM_INFILE, config)
    table_list = list(set(ese_db.get_tables()).difference(set(helpers.skip_tables)))
except Exception as e:
    error_message_box("CRITICAL", f"I could not open the srum file it appears to be corrupt. Error:{str(e)}")
    sys.exit(1)

#Enable to debug when dissect in use
# import debugpy
# debugpy.listen(5678)
# print("Waiting for debugger...")
# debugpy.wait_for_client()

#Display Progress Window
progress = ProgressWindow("SRUM-DUMP 3.0")
progress.start(len(table_list))



#Preload some lookup tables for speed
trans_table = config.get_config("columns_to_translate")
dirty_words = config.get_config("dirty_words")
ads = helpers.ads

#Create the workbook / directory
timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S") 
results_path = pathlib.Path(options.OUT_DIR).joinpath(f"SRUM-DUMP-{timestamp}")
workbook = output.new_workbook( results_path )

#record time and record count for statistics
read_count = 0
for each_table in table_list:

    table_name = config.get_config("known_tables").get(each_table, each_table)
    table_object = ese_db.get_table(each_table)

    #Update progress window
    progress.set_current_table(table_name)
    progress.log_message(next(ads))


    #Define Columns names and add any calculated columns
    column_names = list(map(helpers.column_friendly_names, table_object.column_names))
    calculated_columns = config.get_config("calculated_columns").get(table_name)
    if calculated_columns:
        column_names.extend( calculated_columns.keys() )


    #Reset stats used for records pers second for each table
    start_time = time.time() 
    table_count = 0
    #Create a worksheet and loop through the records
    with output.new_worksheet(workbook, table_name, column_names) as worksheet:
        for each_record in ese_db.get_records(each_table):
            new_row = []
            cell_formats = [None] * len(table_object.column_names)

            #Statistics updating..
            read_count += 1
            table_count += 1
            if read_count % 1000 == 0:
                elapsed_time = time.time() - start_time
                if elapsed_time != 0:
                    progress.update_stats(read_count, table_count // elapsed_time) 

            #Format each value in the row           
            for position, eachcol in enumerate(table_object.column_names):
                out_format = trans_table.get(eachcol)
                embedded_value = each_record.value(eachcol)  
                if not out_format or not embedded_value:
                    new_row.append( embedded_value )
                elif out_format == "APPID":
                    val = ese_db.id_lookup.get(str(embedded_value),'')
                    new_row.append( val )
                    #Colorize the dirty word cells
                    for eachword in dirty_words:
                        if eachword.lower() in val.lower():
                            cell_formats[position] = ("General",f"BOLD:{dirty_words.get(eachword)}")   
                elif out_format == "SID":
                    val = ese_db.id_lookup.get(str(embedded_value),'')
                    new_row.append(val)
                    #Colorize the dirty word cells
                    for eachword in dirty_words:
                        if eachword.lower() in val.lower():
                            cell_formats[position] = ("General",f"BOLD:{dirty_words.get(eachword)}")   
                elif out_format == "OLE":
                    new_row.append( helpers.ole_timestamp(embedded_value) )
                elif out_format == "seconds":
                    new_row.append( embedded_value/86400.0)
                elif out_format[:5] == "FILE:":          
                    val = helpers.file_timestamp(embedded_value)
                    if isinstance(val, datetime.datetime):
                        val = val.strftime(out_format[5:])
                    else:
                        val = embedded_value
                    new_row.append(val)
                elif out_format == "network_interface":
                    val = config.get_config('network_interfaces').get(str(embedded_value), embedded_value)
                    new_row.append( val )
                    #Colorize the dirty word cells
                    if isinstance(val, str):
                        for eachword in dirty_words:
                            if eachword.lower() in val.lower():
                                cell_formats[position] = ("General",f"BOLD:{dirty_words.get(eachword)}")  
                elif out_format == "interface_types":
                    inttype = struct.unpack(">H6B", codecs.decode(format(embedded_value,"016x"),"hex"))[0]
                    new_row.append( config.get_config('interface_types').get(str(inttype),inttype))

            #Add calculated columns to the end
            if calculated_columns:        
                for formula_template in calculated_columns.values():
                    formula = formula_template.replace('#ROW_NUM#', str(table_count + 1))  # Replace row number
                    new_row.append(formula)  # Append the formula

            #add the new row to the table
            output.new_entry(worksheet, new_row, cell_formats)
        #Log that the table is finished
        progress.log_message(f"Table {table_name} contained {table_count} records.\n")


# Remove the default "Sheet" if it exists
if 'Sheet' in workbook.sheetnames:
    del workbook['Sheet']
progress.log_message(f"Finalizing output now...  Total Records: {read_count}.\n")
output.save()
progress.set_current_table("Finished")
progress.log_message(f"Finished!")
progress.finished()
progress.root.mainloop()

