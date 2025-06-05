
import logging
import re

logger = logging.getLogger("srum_dump")
null_handler = logging.NullHandler()

# Add the NullHandler to the root to block all other 3rd party library logs until we are ready for them
logging.root.addHandler(null_handler)

import argparse
import os
import pathlib
import sys
import ctypes
import time
import struct
import codecs
import datetime
import copy_locked
import helpers

# Import the desired UI and DB modules
from ui_tk import get_user_input, get_input_wizard, error_message_box, ProgressWindow
from config_manager import ConfigManager


parser = argparse.ArgumentParser(description="Given an SRUM database it will create an XLS spreadsheet or CSV with analysis of the data in the database.")
parser.add_argument("--SRUM_INFILE", "-i", help="Specify the ESE (.dat) file to analyze. Provide a valid path to the file.")
parser.add_argument("--OUT_DIR", "-o", help="Full path to a working output directory.")
parser.add_argument("--REG_HIVE", "-r", help="If SOFTWARE registry hive is provided then the names of the network profiles will be resolved.")
parser.add_argument("--ESE_ENGINE", "-e", choices=['pyesedb', 'dissect'], default=None, help="Corrupt file? Try a different engine to see if it does better. Options are pyesedb or dissect")
parser.add_argument("--OUTPUT_FORMAT", "-f", choices=['xls', 'csv'], default=None, help="Specify the output format. Options are xls or csv. Default is xls.")
parser.add_argument("--DEBUG","-v", action="store_true",help="Enable verbose logging in srum_dump.log")
parser.add_argument("--NO_CONFIRM","-q", action="store_true",help="Do not show the confirmation dialog box.")
options = parser.parse_args()

# --- Logging Setup ---
log_file_path = None # Initialize in case OUT_DIR isn't set initially
logger.setLevel(logging.INFO) # INFO logging by default
if options.DEBUG:
    logger.setLevel(logging.DEBUG) # Unless you pass --DEBUG or -v
# --- End Logging Setup ---

#If an OUT_DIR was specified on the cli we check it for a config
if options.OUT_DIR and options.SRUM_INFILE:
    config_path = pathlib.Path(options.OUT_DIR).joinpath("srum_dump_config.json")
    config = ConfigManager(config_path)
    if not config_path.is_file():
        error_message_box("Error", "Configuration file not found. Please run the program without the OUT_DIR option first.")
        sys.exit(1)
    options.OUT_DIR = str(config_path.parent)  #We want this to always be the place where config is stored.
else:
    get_input_wizard(options)  #Get paths with wizard
    #Create a config
    config_path = pathlib.Path(options.OUT_DIR).joinpath("srum_dump_config.json")
    config = ConfigManager(config_path)
    #There is no config so lets set some defaults on CLI arguments that were not explicitly set
    #And create a configuration file
    if not config_path.is_file():
        if options.ESE_ENGINE == None:
            options.ESE_ENGINE = "dissect"
        if options.OUTPUT_FORMAT == None:
            options.OUTPUT_FORMAT = "xls"
        config.set_config("dirty_words", helpers.dirty_words)
        config.set_config("known_tables", helpers.known_tables)
        config.set_config("known_sids", helpers.known_sids)     
        config.set_config("network_interfaces", {})
        config.set_config("skip_tables", helpers.skip_tables)
        config.set_config("interface_types", helpers.interface_types)
        config.set_config("column_markups", helpers.column_markups)
        config.save()


# --- Configure File Handler ---
# Now that OUT_DIR is guaranteed to be set, configure the file handler
log_file_path = pathlib.Path(options.OUT_DIR).joinpath("srum_dump.log")
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s')
file_handler = logging.FileHandler(log_file_path)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(log_formatter)
logger.addHandler(file_handler)
logger.info(f"Logging initialized. Log file: {log_file_path}")
logger.info(f"Using options: {options}")
# --- End File Handler Configuration ---


#Check SRUM_INFILE to see if we need to extract a copy of the SRUM
if pathlib.Path(os.environ['SystemRoot']).resolve() in pathlib.Path(options.SRUM_INFILE).parents:
    if ctypes.windll.shell32.IsUserAnAdmin() != 1:
        error_message_box("Error", "The file you selected is locked by the operating system. Please run this program as an administrator or select a different file.")   
        sys.exit(1)
    else:
        success = copy_locked.copy_locked_files(pathlib.Path(options.OUT_DIR))
        options.SRUM_INFILE = str(pathlib.Path(options.OUT_DIR).joinpath("SRUDB.dat"))
        options.REG_HIVE =  str(pathlib.Path(options.OUT_DIR).joinpath("SOFTWARE"))
        options.OUT_DIR = str(pathlib.Path(options.OUT_DIR))
        if not success:
            sys.exit(1)


#If a registry hive is provided extract SIDS and network profiles and put it in the config file
if options.REG_HIVE:
    network_interfaces = helpers.load_interfaces(options.REG_HIVE)
    known_sids = helpers.known_sids
    registry_sids = helpers.load_registry_sids(options.REG_HIVE)
    srum_table_names = helpers.load_srum_table_names(options.REG_HIVE)
    config.set_config("known_tables", srum_table_names)
    config.save()
    if network_interfaces:
        config.set_config("network_interfaces", network_interfaces)
        config.save()
    if registry_sids:
        known_sids.update(registry_sids)
        config.set_config("known_sids", known_sids)

    
#Open the srum and allow the SRUDbIdMapTable to load then add it to the config
#Select ESE engine
if options.ESE_ENGINE == "pyesedb":
    from db_ese import srum_database
else:
    from db_dissect import srum_database


#Open database using specified engine
try:
    ese_db = srum_database(options.SRUM_INFILE, config)
    table_list = list(set(ese_db.get_tables()).difference(set(helpers.skip_tables)))
except Exception as e:
    error_message_box("CRITICAL", f"I could not open the srum file it appears to be corrupt. Error:{str(e)}")
    sys.exit(1)

config.delete_config("known_sids")
config.set_config("SRUDbIdMapTable", ese_db.id_lookup)
config.save() 

#Let User confirm the settings and paths.  Then save for reuse next time
if not options.NO_CONFIRM:
    get_user_input(options)

#Load any configuration changes made during confirmation
config.load()

#Select Output Engine and create output object
if options.OUTPUT_FORMAT == "csv":
    from output_csv import OutputCSV
    output = OutputCSV()
else:
    from output_xlsx import OutputXLSX
    output = OutputXLSX()


logger.debug("Starting main processing.")
#Enable to debug when dissect in use
# import debugpy
# debugpy.listen(5678)
# print("Waiting for debugger...")
# debugpy.wait_for_client()

#Display Progress Window
progress = ProgressWindow("SRUM-DUMP 3.1")
progress.start(len(table_list) + 2)


#Preload some lookup tables for speed
column_markups = config.get_config("column_markups")
dirty_words = config.get_config("dirty_words")
app_ids = config.get_config("SRUDbIdMapTable")
ads = helpers.ads

#Create the workbook / directory
timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S") 
results_path = pathlib.Path(options.OUT_DIR).joinpath(f"SRUM-DUMP-{timestamp}")
workbook = output.new_workbook( results_path )

#record time and record count for statistics
read_count = 0
try:  # Start of the main processing block
    for each_table in table_list:
        #Get table objects and name
        table_name = config.get_config("known_tables").get(each_table, each_table)
        table_object = ese_db.get_table(each_table)
        logger.info(f"Now Processing table {table_name}.")

        #Update progress window
        progress.set_current_table(table_name)
        progress.log_message(next(ads))

       # Get column markups for this table and combine with defaults
        all_table_markups = column_markups.get("All Tables", {})
        table_specific_markups = column_markups.get(table_name, {}) #They maybe in config as friendly names
        table_specific_markups2 = column_markups.get(each_table, {}) #They maybe in config as GUIDS (friendlies change)
   
        #We will now combine the markups from ALL_TABLES and the table specfic uverrides (either by friendly name of guid)
        current_markups = {}
        # Collect all unique column names from all three sources
        all_columns = set(all_table_markups.keys()).union(set(table_specific_markups.keys()), set(table_specific_markups2.keys()))
        # Merge attributes for each column
        for column in all_columns:
            # Start with default attributes for this column
            column_attrs = all_table_markups.get(column, {}).copy()
            
            # Update with attributes from table_specific_markups
            table_attrs1 = table_specific_markups.get(column, {})
            column_attrs.update(table_attrs1)
            
            # Update with attributes from table_specific_markups2
            table_attrs2 = table_specific_markups2.get(column, {})
            column_attrs.update(table_attrs2)
            
            # Store the merged attributes for this column
            current_markups[column] = column_attrs

        #Get column names and configuration settings for processing
        column_names = list(table_object.column_names)
        display_names = [current_markups.get(col, {}).get("friendly_name", col) for col in column_names]
        calculated_columns = {col: markup["formula"] for col, markup in current_markups.items() if "formula" in markup}
        #calculated_formats = {col: markup["style"] for col, markup in current_markups.items() if "formula" in markup}
        column_styles = {col: markup["style"] for col, markup in current_markups.items() if "style" in markup}
        trans_table = {col: markup["translate"] for col, markup in current_markups.items() if "translate" in markup}
        specified_widths = {col: markup["width"] for col, markup in current_markups.items() if "width" in markup}

        #Add calculated columns to column lists before important styling calculations and processing happens
        logger.info(f"Table {table_name} contains columns {str(display_names)}")
        if calculated_columns:
            display_names.extend( calculated_columns.keys() )
            column_names.extend( calculated_columns.keys() )

        #Set Column Widths. Default to column name width - Override based on column_markups config
        #This must be done before the worksheet is created
        column_widths = [len(display_name) for display_name in display_names]
        for scol,swidth in specified_widths.items():
            if scol in column_names:
                column_widths[ column_names.index(scol) ] = int(swidth)

        #Reset stats used for records pers second for each table
        start_time = time.time() 
        table_count = 0
        #Create a worksheet and loop through the records
        with output.new_worksheet(workbook, table_name, display_names, column_widths) as worksheet:
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

                #Format each column in the row           
                for position, eachcol in enumerate(table_object.column_names):
                    out_format = trans_table.get(eachcol, None)
                    embedded_value = each_record.value(eachcol)
                  
                    if (not out_format) or (not embedded_value) or (embedded_value == "Empty"):  #Default
                        val = embedded_value
                        new_row.append( val )
                    elif out_format == "APPID":
                        val = app_ids.get(str(embedded_value),'')
                        new_row.append( val )
                    elif out_format == "SID":
                        val = app_ids.get(str(embedded_value),'')
                        new_row.append(val)
                    elif out_format == "OLE":
                        val = helpers.ole_timestamp(embedded_value)
                        cell_formats[position] = "datetime"
                        new_row.append( val )
                    elif out_format == "seconds":
                        val = embedded_value/86400.0
                        new_row.append( val )
                    elif out_format[:5] == "FILE:":          
                        val = helpers.file_timestamp(embedded_value)
                        cell_formats[position] = "datetime"
                        new_row.append(val)
                    elif out_format == "network_interface":
                        val = config.get_config('network_interfaces').get(str(embedded_value), embedded_value)
                        new_row.append( val )
                    elif out_format == "interface_types":
                        inttype = struct.unpack(">H6B", codecs.decode(format(embedded_value,"016x"),"hex"))[0]
                        val = config.get_config('interface_types').get(str(inttype),inttype)
                        new_row.append( val )

                    #Colorize the dirty word cells overriding any previous formatting
                    if isinstance(val, str):
                        for eachword in dirty_words:
                            if eachword.lower() in val.lower():
                                cell_formats[position] = dirty_words.get(eachword)  

                    #Apply named style if it is defined in the column_markups
                    if not cell_formats[position] and eachcol in column_styles:
                        cell_formats[position] = column_styles.get(eachcol)

                #Done iterating over each column for this row
                #Add calculated columns to the end of this row
                if calculated_columns:        
                    for col, formula in calculated_columns.items():
                        row_calcs = re.findall(r'#ROW_NUM[+-]\d+#', formula)
                        for calc in row_calcs:
                            operator = '+' if '+' in calc else '-'
                            number = int(calc.split(operator)[-1][:-1])
                            base_row = table_count + 1
                            result = base_row + number if operator == '+' else base_row - number
                            result = max(result, 0)
                            formula = formula.replace(calc, str(result))
                        value = formula.replace('#ROW_NUM#', str(table_count + 1))
                        new_row.append( value )
                        cell_formats.append( current_markups.get(col).get("style") )

                #add the new row to the table
                output.new_entry(worksheet, new_row, cell_formats)
            
            #Log that the table is finished
            logger.info(f"Table {table_name} contained {table_count} records.")
            progress.log_message(f"Table {table_name} contained {table_count} records.\n")

    progress.set_current_table(f"Writing Output Files.")
    progress.log_message(f"Writing Output Files...  Please be patient\n")
    progress.log_message(next(ads))
    output.save()
    progress.log_message(next(ads))
    progress.set_current_table(f"Finished")
    progress.log_message(f"Finished!  Total Records: {read_count}.\n")
    progress.finished()
    logger.info("Main processing finished successfully.")
    # --- End of Finalization steps ---

except Exception as main_exception:  # Aligned with the 'try' approximatly on line 170 (main loop)
    logger.exception(f"An unexpected error occurred during main processing: {main_exception}")
    error_message_box("CRITICAL ERROR", f"An unexpected error occurred: {main_exception}\nCheck the log file for details:\n{log_file_path}")
finally:  # Aligned with the 'try' approximatly on line 170 (main loop)
    if 'progress' in locals() and progress.root:
        try:
            progress.root.mainloop()
        except Exception as ui_exception:
            logger.error(f"Error during UI mainloop: {ui_exception}")
    logger.debug("Application exiting.")
