import sys
import os
import pathlib
from srum_dump.gui import SRUMDumpGUI
from srum_dump.xlsx import XLSXHandler
from srum_dump.srum import ESEDBHandler
from srum_dump.registry import RegistryHandler
from srum_dump.utils import BinarySIDtoStringSID, blob_to_string, ole_timestamp, file_timestamp

def main():
    gui = SRUMDumpGUI()
    user_inputs = gui.run()
    if not user_inputs:
        return

    xlsx_handler = XLSXHandler(user_inputs["XLSX_TEMPLATE"], user_inputs["XLSX_OUTFILE"])
    xlsx_handler.load_template()

    registry_handler = RegistryHandler(user_inputs["REG_HIVE"], xlsx_handler.template_lookups)
    registry_handler.load_registry_sids()
    registry_handler.load_interfaces()

    ese_handler = ESEDBHandler(user_inputs["SRUM_INFILE"], xlsx_handler.template_tables, xlsx_handler.template_lookups, registry_handler.sids)
    if not ese_handler.open_ese_db():
        return

    ese_handler.process_srum(xlsx_handler.output_workbook)
    ese_handler.close_ese_db()
    xlsx_handler.save_output()

    print("Done.")

if __name__ == "__main__":
    main()
