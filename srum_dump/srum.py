import pyesedb
import struct
import uuid
import time
import codecs
from srum_dump.utils import BinarySIDtoStringSID, blob_to_string, ole_timestamp, file_timestamp

class ESEDBHandler:
    def __init__(self, ese_file, template_tables, template_lookups, id_lookup):
        self.ese_file = ese_file
        self.template_tables = template_tables
        self.template_lookups = template_lookups
        self.id_lookup = id_lookup
        self.ese_db = None

    def open_ese_db(self):
        try:
            self.ese_db = pyesedb.file()
            self.ese_db.open(self.ese_file)
        except Exception as e:
            print("Error opening SRUM file:", str(e))
            return False
        return True

    def close_ese_db(self):
        self.ese_db.close()

    def get_table_name(self, ese_table):
        if ese_table.name in self.template_tables:
            return self.template_tables.get(ese_table.name)[0]
        else:
            return ese_table.get_name()

    def get_record(self, ese_table, row_num):
        retry = 5
        if row_num >= self.get_record_count(ese_table):
            return None
        while retry:
            try:
                ese_row = ese_table.get_record(row_num)
            except Exception as e:
                retry -= 1
                time.sleep(0.1)
                error = e
            else:
                break
        else:
            table_name = self.get_table_name(ese_table)
            print(f"Skipping corrupt row {row_num} in the {table_name} table. Because {str(error)}")
            ese_row = None
        return ese_row

    def get_record_count(self, ese_table):
        retry = 5
        while retry:
            try:
                total_recs = ese_table.get_number_of_records()
            except:
                retry -= 1
                time.sleep(0.1)
            else:
                break
        else:
            table_name = self.get_table_name(ese_table)
            print(f"Table {table_name} has an invalid number of records. {str(total_recs)}")
            total_recs = 0
        return total_recs
    
        
    def smart_retrieve(ese_table, ese_record_num, column_number):
        """Given a row and column will determine the format and retrieve a value from the ESE table"""
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
            col_data = "" if not col_data else codecs.encode(col_data,"HEX")
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
        if col_data==None:
            col_data = "Empty"
        return col_data
