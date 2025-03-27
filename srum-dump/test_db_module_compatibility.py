import unittest
from unittest.mock import Mock
import pathlib

# Import the two implementations
from db_dissect import srum_database as DissectSRUMDatabase  # Rename for clarity
from db_ese import srum_database as PyesedbSRUMDatabase  # Rename for clarity

class TestSRUMDatabaseCompatibility(unittest.TestCase):
    def setUp(self):
        # Provide a path to a test SRUDB.dat file (replace with your actual file path)
        self.test_db_path = pathlib.Path("C:/Users/mark/Desktop/SRU/SRU/SRUDB.dat")
        if not self.test_db_path.exists():
            raise FileNotFoundError("Please provide a valid test SRUDB.dat file path")

        # Initialize both database instances
        self.dissect_db = DissectSRUMDatabase(self.test_db_path)
        self.pyesedb_db = PyesedbSRUMDatabase(self.test_db_path)

    def tearDown(self):
        # Close both database connections
        self.dissect_db.close()
        self.pyesedb_db.close()

    def test_connect(self):
        """Test that connect() works and doesn't raise unexpected errors."""
        # Both are connected in setUp, so just verify they are active
        self.assertIsNotNone(self.dissect_db.sru)
        self.assertIsNotNone(self.pyesedb_db.db)

    def test_close(self):
        """Test that close() properly disconnects the database."""
        self.dissect_db.close()
        self.pyesedb_db.close()
        self.assertIsNone(self.dissect_db.sru)
        self.assertIsNone(self.pyesedb_db.db)

    def test_get_tables(self):
        """Test that get_tables() yields the same table names."""
        dissect_tables = list(self.dissect_db.get_tables())
        pyesedb_tables = list(self.pyesedb_db.get_tables())
        self.assertEqual(dissect_tables, pyesedb_tables, "Table names differ between implementations")

    def test_get_table(self):
        """Test that get_table() returns tables with identical column names."""
        # Use a known table name (e.g., 'SruDbIdMapTable' from the example)
        table_name = "SruDbIdMapTable"
        dissect_table = self.dissect_db.get_table(table_name)
        pyesedb_table = self.pyesedb_db.get_table(table_name)

        self.assertIsNotNone(dissect_table, "Dissect table not found")
        self.assertIsNotNone(pyesedb_table, "Pyesedb table not found")
        self.assertEqual(
            dissect_table.column_names,
            pyesedb_table.column_names,
            f"Column names differ for table {table_name}"
        )

    def test_get_records(self):
        """Test that get_records() yields records with identical values."""
        table_name = "SruDbIdMapTable"  # Replace with a table you know exists
        dissect_records = list(self.dissect_db.get_records(table_name))[:5000]  # Limit to 5 for speed
        pyesedb_records = list(self.pyesedb_db.get_records(table_name))[:5000]

        self.assertEqual(len(dissect_records), len(pyesedb_records), "Record counts differ")

        import debugpy
        debugpy.listen(5678)
        print("Waiting for debugger...")
        debugpy.wait_for_client()
        
        # Compare values for each column in each record
        for d_rec, p_rec in zip(dissect_records, pyesedb_records):
            for col_name in d_rec.column_names:
                d_value = d_rec.value(col_name)
                p_value = p_rec.value(col_name)
                self.assertEqual(
                    d_value,
                    p_value,
                    f"Values differ for column {col_name}: {d_value} vs {p_value}"
                )

    def test_invalid_table(self):
        """Test that both raise an exception for a nonexistent table."""
        invalid_table = "NonExistentTable123"
        with self.assertRaises(Exception):
            self.dissect_db.get_table(invalid_table)
        with self.assertRaises(Exception):
            self.pyesedb_db.get_table(invalid_table)

    def test_record_value_types(self):
        """Test that record.value() handles various column types consistently."""
        # This test would ideally use a mock table with known column types.
        # Since we don’t have that, we’ll assume 'SruDbIdMapTable' has some known columns.
        table_name = list(self.dissect_db.get_tables())[-3]
        d_table = self.dissect_db.get_table(table_name)
        p_table = self.pyesedb_db.get_table(table_name)

        d_records = list(self.dissect_db.get_records(table_name))
        p_records = list(self.pyesedb_db.get_records(table_name))

        if not d_records or not p_records:
            self.skipTest("No records available in SruDbIdMapTable for type testing")

        d_rec, p_rec = d_records[0], p_records[0]
        for col_name in d_table.column_names:
            d_val = d_rec.value(col_name)
            p_val = p_rec.value(col_name)
            self.assertEqual(
                type(d_val),
                type(p_val),
                f"Type mismatch for column {col_name}: {type(d_val)} vs {type(p_val)}"
            )
            self.assertEqual(
                d_val,
                p_val,
                f"Value mismatch for column {col_name}: {d_val} vs {p_val}"
            )

    def test_not_connected(self):
        """Test that methods raise exceptions when not connected."""
        self.dissect_db.close()
        self.pyesedb_db.close()

        with self.assertRaises(Exception):
            list(self.dissect_db.get_tables())
        with self.assertRaises(Exception):
            list(self.pyesedb_db.get_tables())

if __name__ == "__main__":
    unittest.main()