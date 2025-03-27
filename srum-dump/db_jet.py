import pathlib
import struct
import codecs
import uuid
from datetime import datetime

# IronPython-specific imports for .NET integration
import clr
import sys
import os
from System import Reflection  # For assembly inspection

# Add the current directory to sys.path
current_dir = os.getcwd()
if current_dir not in sys.path:
    sys.path.append(current_dir)

# Specify just the DLL filename
dll_name = "esent.interop.dll"
dll_path = os.path.join(current_dir, dll_name)
if not os.path.exists(dll_path):
    print(f"Error: {dll_path} not found in {current_dir}")
    sys.exit(1)

# Try loading the assembly and inspect it
try:
    # Attempt clr.AddReference first
    clr.AddReference(dll_name)
    print("Successfully loaded esent.interop.dll via clr.AddReference")
except Exception as e:
    print(f"clr.AddReference failed: {e}")
    # Fallback to clr.AddReferenceToFile
    try:
        clr.AddReferenceToFile(dll_name)
        print("Successfully loaded esent.interop.dll via clr.AddReferenceToFile")
    except Exception as e2:
        print(f"clr.AddReferenceToFile failed: {e2}")
        # Inspect the assembly manually
        try:
            asm = Reflection.Assembly.LoadFile(dll_path)
            print(f"Assembly loaded manually: {asm.FullName}")
        except Exception as e3:
            print(f"Manual assembly load failed: {e3}")
            sys.exit(1)

# Import required classes and enums
try:
    from Microsoft.Isam.Esent.Interop import (
        JET_INSTANCE, JET_SESID, JET_DBID, JET_TABLEID,
        JET_coltyp, JET_param, Api, InstanceParameters, JET_RETRIEVE_COLUMN
    )
    from Microsoft.Isam.Esent.Interop import OpenDatabaseFlags as OpenDBFlags
    from Microsoft.Isam.Esent.Interop import OpenTableGrbit as OpenTblGrbit
    from Microsoft.Isam.Esent.Interop import MoveGrbit
    from Microsoft.Isam.Esent.Interop import EsentException
    print("Imported Microsoft.Isam.Esent.Interop namespace successfully")
except ImportError as e:
    print(f"Namespace import failed: {e}")
    sys.exit(1)

from System import IntPtr, DateTime
from System.Text import Encoding

# Assuming these helper functions are defined elsewhere
from helpers import known_tables, skip_tables
from helpers import ole_timestamp, blob_to_string, BinarySIDtoStringSID

# Rest of your code remains unchanged...
class EsentTableWrapper:
    def __init__(self, sesid, dbid, table_name):
        self.sesid = sesid
        self.dbid = dbid
        self.table_name = table_name
        self.tableid = JET_TABLEID()
        Api.JetOpenTable(self.sesid, self.dbid, self.table_name, None, 0, OpenTableGrbit.ReadOnly, self.tableid)
        self.column_defs = Api.GetTableColumns(self.sesid, self.tableid)
        self.column_names = [col.Name for col in self.column_defs]
        self.column_types = [col.Coltyp for col in self.column_defs]
        self.column_ids = dict((col.Name, col.Columnid) for col in self.column_defs)

    def records(self):
        """Yield records from the table."""
        Api.JetMove(self.sesid, self.tableid, JET_Move.First, 0)  # Move to first record
        while True:
            yield EsentRecordWrapper(self)
            try:
                Api.JetMove(self.sesid, self.tableid, JET_Move.Next, 0)  # Move to next record
            except EsentException:  # End of table
                break

    def close(self):
        """Close the table."""
        Api.JetCloseTable(self.sesid, self.tableid)

class EsentRecordWrapper:
    """Wrapper class to access record data using Microsoft.Isam.Esent.Interop."""
    def __init__(self, table):
        self.table = table
        self.sesid = table.sesid
        self.tableid = table.tableid
        self.column_names = table.column_names
        self.column_types = table.column_types
        self.column_ids = table.column_ids

    def value(self, column_name):
        """Return the value of the specified column."""
        try:
            column_index = self.column_names.index(column_name)
            col_type = self.column_types[column_index]
            col_id = self.column_ids[column_name]

            # Retrieve column data
            data, actual_size = Api.RetrieveColumn(self.sesid, self.tableid, col_id)
            if data is None:
                return "Empty"

            # Handle different column types
            if col_type == JET_coltyp.Binary:
                return "" if not data else codecs.encode(data, "HEX").decode('ascii')
            elif col_type == JET_coltyp.DateTime:
                if not data:
                    return ""
                # Convert .NET DateTime (stored as ticks) to Python datetime
                ticks = struct.unpack("<q", data)[0]
                dt = DateTime.FromFileTime(ticks)
                return datetime(dt.Year, dt.Month, dt.Day, dt.Hour, dt.Minute, dt.Second)
            elif col_type in [JET_coltyp.Text, JET_coltyp.LongText, JET_coltyp.LongBinary]:
                return blob_to_string(data)
            elif col_type in [JET_coltyp.Long, JET_coltyp.Short]:
                return int.from_bytes(data, byteorder='little', signed=True)
            elif col_type == JET_coltyp.IEEEDouble:
                return struct.unpack("<d", data)[0]
            else:
                return str(data)  # Fallback for unhandled types

        except ValueError:
            raise ValueError(f"Column '{column_name}' not found in record")
        except Exception as e:
            raise Exception(f"Error retrieving column '{column_name}': {e}")

class srum_database:
    def __init__(self, db_path, config):
        """Initialize the database class with the database file path."""
        self.db_path = pathlib.Path(db_path)
        self.config = config
        self.instance = JET_INSTANCE()
        self.sesid = JET_SESID()
        self.dbid = JET_DBID()
        self.table_to_name = known_tables
        self.name_to_table = dict((v, k) for k, v in known_tables.items())
        self.skip_tables = skip_tables
        self.connect()
        self.id_lookup = {}
        self.load_srumid_lookups()

    def connect(self):
        """Establish a connection to the ESE database."""
        if not self.db_path.is_file():
            raise ValueError("The specified file path does not exist")

        try:
            # Initialize ESENT instance
            Api.JetCreateInstance(self.instance, "SRUMInstance")
            Api.JetSetSystemParameter(self.instance, JET_SESID.Nil, JET_param.Recovery, "off", None)
            Api.JetInit(self.instance)

            # Begin session
            Api.JetBeginSession(self.instance, self.sesid, None, None)

            # Open database
            Api.JetOpenDatabase(self.sesid, str(self.db_path), None, self.dbid, OpenDatabaseFlags.ReadOnly)
        except Exception as e:
            raise Exception(f"Error connecting to database: {e}")

    def close(self):
        """Close the database connection."""
        if self.sesid.Value != JET_SESID.Nil.Value:
            Api.JetCloseDatabase(self.sesid, self.dbid, 0)
            Api.JetEndSession(self.sesid, 0)
            Api.JetTerm(self.instance)
            self.sesid = JET_SESID()
            self.dbid = JET_DBID()
            self.instance = JET_INSTANCE()

    def load_srumid_lookups(self):
        """Loads SRUMID numbers from the SRUM database."""
        lookups = self.config.get_config("known_sids")
        table = self.get_table("{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}")  # Assuming this is the ID map table
        for rec in self.records(table):
            id_type = rec.value("IdType")
            id_index = rec.value("IdIndex")
            id_blob = rec.value("IdBlob") if "IdBlob" in rec.column_names else ""
            if id_type == 3 and id_blob != "Empty":
                id_blob = BinarySIDtoStringSID(bytes.fromhex(id_blob), lookups)
            else:
                id_blob = blob_to_string(id_blob)
            self.id_lookup[str(id_index)] = id_blob
        table.close()

    def get_tables(self):
        """Yield table names one at a time from the database."""
        if self.sesid.Value == JET_SESID.Nil.Value:
            raise Exception("Database not connected. Call connect() first.")
        table_names = Api.GetTableNames(self.sesid, self.dbid)
        for table_name in table_names:
            yield table_name

    def get_table(self, table_name):
        """Return the table object for the specified table name."""
        if self.sesid.Value == JET_SESID.Nil.Value:
            raise Exception("Database not connected. Call connect() first.")
        try:
            return EsentTableWrapper(self.sesid, self.dbid, table_name)
        except Exception as e:
            raise Exception(f"Error retrieving table {table_name}: {e}")

    def get_records(self, table_name):
        """Yield records one at a time from the specified table."""
        table = self.get_table(table_name)
        if not table:
            raise Exception(f"Table {table_name} not found.")
        try:
            for record in table.records():
                yield record
        except Exception as e:
            raise Exception(f"Error retrieving records from {table_name}: {e}")
        finally:
            table.close()

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
        for record in db.get_records(table_name):
            for eachcol in current_table.column_names:
                print(record.value(eachcol), end=" ")
            if record_count < 5:
                print(record)
                record_count += 1
            else:
                break
    db.close()