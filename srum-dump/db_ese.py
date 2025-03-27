import pathlib
import pyesedb
import struct
import codecs
import uuid
import time

from pyesedb import table

from helpers import blob_to_string, BinarySIDtoStringSID, known_tables, skip_tables
from helpers import ole_timestamp

class PyesedbTableWrapper:
    def __init__(self, table_instance):
        self.table = table_instance
        self.column_names =[]
        self.column_types =[]

    def __getattr__(self, name):
        return getattr(self.table, name)
    
    def get_number_of_records(self, *args, **kwargs):
        start = time.time()
        while time.time() - start < 1.5:
            try:
                result = self.table.number_of_records
            except Exception as e:
                time.sleep(0.01)
                pass
            else:
                return result
        raise e
    
    def get_record(self, *args, **kwargs):
        start = time.time()
        while time.time() - start < 1.5:
            try:
                result = self.table.get_record(*args,**kwargs)
            except Exception as e:
                time.sleep(0.01)
                pass
            else:
                return result
        raise e


class PyesedbRecordWrapper:
    """Wrapper class to make pyesedb records compatible with dissect.esedb record access."""
    def __init__(self, record, table):
        self.record = record
        self.table = table
        self.column_names = table.column_names
        self.column_types = table.column_types

    def __getattr__(self, name):
        """Allow attribute-style access to record values."""
        try:
            column_index = self.column_names.index(name)
            return self.record.get_value_data(column_index)
        except ValueError:
            raise AttributeError(f"Column '{name}' not found in record")

    def value(self, column_name):
        """Return the value of the specified column."""
        try:
            column_index = self.column_names.index(column_name)
            col_data = self.record.get_value_data(column_index)
            col_type = self.column_types[column_index]
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
                col_data = 0 if not col_data else str(uuid.UUID(bytes = col_data))
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
                col_data = blob_to_string(col_data)
                #col_data = "" if not col_data else codecs.encode(col_data,"HEX")
            elif col_type == pyesedb.column_types.LARGE_TEXT:
                col_data = blob_to_string(col_data)
            elif col_type == pyesedb.column_types.NULL:
                pass
            elif col_type == pyesedb.column_types.SUPER_LARGE_VALUE:
                col_data = "" if not col_data else codecs.encode(col_data,"HEX")
            elif col_type == pyesedb.column_types.TEXT:
                col_data = blob_to_string(col_data)  
            else:
                col_data = blob_to_string(col_data)    
            if col_data==None or col_data=='':
                col_data = "Empty"
            return col_data
        except ValueError:
            raise ValueError(f"Column '{column_name}' not found in record")

    def __str__(self):
        """Provide a string representation of the record."""
        values = {col: self.record.get_value_data(i) for i, col in enumerate(self.column_names)}
        return str(values)

class srum_database(object):
    def __init__(self, db_path, config):
        """Initialize the db_ese class with the database file path."""
        self.db_path = pathlib.Path(db_path)
        self.db = None
        self.config = config
        self.table_to_name = known_tables
        self.name_to_table = dict((v,k) for k,v in known_tables.items())
        self.skip_tables = skip_tables
        self.id_lookup = {}
        self.connect()
        self.load_srumid_lookups()

    def connect(self):
        """Establish a connection to the ESE database."""
        if not self.db_path.is_file():
            raise ValueError("The specified file path does not exist")
        try:
            self.db = pyesedb.file()
            self.db.open(str(self.db_path))
        except Exception as e:
            raise Exception(f"Error connecting to database: {e}")
        
    def close(self):
        """Close the database connection."""
        if self.db:
            self.db.close()
            self.db = None

    def get_tables(self):
        """Yield table names one at a time from the database."""
        if not self.db:
            raise Exception("Database not connected. Call connect() first.")
        table_count = self.db.get_number_of_tables()
        for i in range(table_count):
            yield self.db.get_table(i).get_name()

    def get_table(self, table_name):
        """Return the table object for the specified table name."""
        if not self.db:
            raise Exception("Database not connected. Call connect() first.")
        try:
            tbl = PyesedbTableWrapper(self.db.get_table_by_name(table_name))
            tbl.column_names = [col.name for col in tbl.table.columns]
            tbl.column_types = [col.type for col in tbl.table.columns]
            return tbl
        except Exception as e:
            raise Exception(f"Error retrieving table {table_name}: {e}")
        

    def get_records(self, table_name):
        """Yield records one at a time from the specified table."""
        table = self.get_table(table_name)
        if not table:
            raise Exception(f"Table {table_name} not found.")
        
        try:
            num_records = table.get_number_of_records()
        except Exception as e:
            num_records = 0
            print(f"Error retrieving number of records from {table_name}: {e}")
        
        try:
            for i in range(num_records):
                yield PyesedbRecordWrapper(table.get_record(i), table)
        except Exception as e:
            raise Exception(f"Error retrieving records from {table_name}: {e}")

    def load_srumid_lookups(self):
        """loads the SRUMID numbers from the SRUM database"""
        lookups = self.config.get_config("known_sids")
        for rec_entry in self.get_records('SruDbIdMapTable'):
            IdType = int.from_bytes(rec_entry.record.get_value_data(0),"little") #IdType
            IdIndex = int.from_bytes(rec_entry.record.get_value_data(1), "little") #IdIndex
            IdBlob = rec_entry.record.get_value_data(2) #IdBlob
            if IdType==3 and IdBlob:
                IdBlob = BinarySIDtoStringSID(IdBlob, lookups)
            else:
                IdBlob = blob_to_string(IdBlob)
            self.id_lookup[str(IdIndex)] = IdBlob



# Example usage with generators
if __name__ == "__main__":
    db_path = "C:/Users/mark/Desktop/SRU/SRU/SRUDB.dat"
    db = srum_database(db_path)
    for table_name in db.get_tables():
        print(table_name, db.table_to_name.get(table_name, "Unknown"))
        if table_name in db.skip_tables:
            continue
        current_table = db.get_table(table_name)
        print(current_table.column_names)
        record_count = 0
        for record in db.get_records(table_name):
            for eachcol in current_table.column_names:
                print(record.value(eachcol),end=" ")
            if record_count < 5:
                print(record)
                record_count += 1
            else:
                break
    db.close()