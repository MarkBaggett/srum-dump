import pathlib
import struct
import codecs
import uuid
from datetime import datetime

from dissect.esedb import EseDB
from dissect.esedb.tools.sru import SRU, Entry
from dissect.esedb.c_esedb import JET_coltyp
from dissect.util.ts import oatimestamp

from helpers import known_tables, skip_tables
from helpers import ole_timestamp, blob_to_string, BinarySIDtoStringSID

class DissectESETableWrapper:
    def __init__(self, table):
        self.table = table
        self.column_names = [col.name for col in self.table.columns]
        self.column_types = [col.type for col in self.table.columns]

    def __getattr__(self, name):
        return getattr(self.table, name)

class DissectESERecordWrapper(Entry):
    """Wrapper class to make pyesedb records compatible with dissect.esedb record access."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.column_names = [col.name for col in self.table.columns]
        self.column_types = [col.type for col in self.table.columns]


    def value(self, column_name):
        """Return the value of the specified column."""
        try:
            column_index = self.column_names.index(column_name)
            col_data = getattr(self.record,column_name)
            col_type = self.column_types[column_index]
            if col_type == JET_coltyp.Binary:
                col_data = "" if not col_data else codecs.encode(col_data,"HEX")
            elif col_type == JET_coltyp.DateTime:
                if not col_data:
                    col_data = ""
                else:
                    col_data = oatimestamp(col_data)
                    col_data = col_data.replace(tzinfo=None)
            elif col_type in [JET_coltyp.Text, JET_coltyp.LongText, JET_coltyp.LongBinary]:
                col_data = blob_to_string(col_data)
  
            if col_data==None or col_data=='':
                col_data = "Empty"
            elif "int" in type(col_data).__name__:
                col_data = int(col_data)
            elif "float" in type(col_data).__name__:
                col_data = float(col_data)
            return col_data
        except ValueError:
            raise ValueError(f"Column '{column_name}' not found in record")

class srum_database(object):
    def __init__(self, db_path, config):
        """Initialize the db_ese class with the database file path."""
        self.db_path = pathlib.Path(db_path)
        self.config = config
        self.file_handle = None
        self.sru = None
        self.table_to_name = known_tables
        self.name_to_table = dict((v,k) for k,v in known_tables.items())
        self.skip_tables = skip_tables
        self.connect()
        self.id_lookup = {}
        self.load_srumid_lookups()

    def connect(self):
        """Establish a connection to the ESE database."""
        if not self.db_path.is_file():
            raise ValueError("The specified file path does not exist")
        try:
            self.file_handle = self.db_path.open("rb")
            self.sru = SRU(self.file_handle)
        except Exception as e:
            raise Exception(f"Error connecting to database: {e}")

    def close(self):
        """Close the database connection."""
        if self.sru:
            self.file_handle.close()
            self.sru = None
            self.file_handle = None

    def load_srumid_lookups(self):
        """loads the SRUMID numbers from the SRUM database"""

        lookups = self.config.get_config("known_sids")
        for id,rec_entry in self.sru.id_map.items():
            IdType = getattr(rec_entry, "IdType") 
            IdIndex = getattr(rec_entry, "IdIndex")
            if not hasattr(rec_entry, "IdBlob"):
                IdBlob = b""
            else:
                IdBlob = getattr(rec_entry, "IdBlob")
            if IdType==3 and IdBlob:
                IdBlob = BinarySIDtoStringSID(IdBlob, lookups)
            else:
                IdBlob = blob_to_string(IdBlob)
            self.id_lookup[str(IdIndex)] = IdBlob

    def get_tables(self):
        """Yield table names one at a time from the database."""
        if not self.sru:
            raise Exception("Database not connected. Call connect() first.")
        for table in self.sru.esedb.tables():
            yield table.name

    def get_table(self, table_name):
        """Return the table object for the specified table name."""
        if not self.sru:
            raise Exception("Database not connected. Call connect() first.")
        try:
            tbl = DissectESETableWrapper(self.sru.get_table(table_guid=table_name))
            return tbl
        except Exception as e:
            raise Exception(f"Error retrieving table {table_name}: {e}")

    def get_records(self, table_name):
        """Yield records one at a time from the specified table."""
        table = self.get_table(table_name)
        if not table:
            raise Exception(f"Table {table_name} not found.")
        try:
            for record in table.records():
                yield DissectESERecordWrapper(self, table, record)
        except Exception as e:
            raise Exception(f"Error retrieving records from {table_name}: {e}")

# Example usage with generators
if __name__ == "__main__":
    db_path = "C:/Users/mark/Desktop/SRU/SRU/SRUDB.dat"
    
    from config_manager import ConfigManager
    config = ConfigManager("C:/Users/mark/Documents/output/srum_dump_config.json")

    db = srum_database(db_path, config)

    print("Tables:")
    for table_name in db.get_tables():
        print(table_name, db.table_to_name.get(table_name, "Unknown"))
        record_count = 0
        if table_name in db.skip_tables:
            continue
        current_table = db.get_table(table_name)
        #Columns are current_table.columns
        for record in db.get_records(table_name):
            for eachcol in current_table.column_names:
                print(record.value(eachcol),end=" ")
            if record_count < 5:
                print(record)
                record_count += 1
            else:
                break
    db.close()