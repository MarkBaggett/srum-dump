from pathlib import Path
import csv


class OutputCSV:
    """
    A class for writing CSV “workbooks”. In this design, a workbook is simply a directory,
    and each worksheet is a CSV file managed by a context manager.
    """
    def __init__(self):
        self.wb = None
        self.path = None

    def new_workbook(self, path: Path):
        """
        Creates a directory to act as the workbook.
        :param path: A pathlib.Path for the workbook directory.
        :return: The Path object representing the workbook directory.
        """
        self.path = path
        if not path.exists():
            path.mkdir(parents=True)
        return path
    
    def save(self):
        return

    class CSVWorksheetContext:
        def __init__(self, file_path: Path, column_headers: list):
            self.file_path = file_path
            self.column_headers = column_headers
            self.file = None
            self.writer = None

        def __enter__(self):
            # Open the CSV file and write the header row.
            self.file = open(self.file_path, mode='w', newline='')
            self.writer = csv.writer(self.file)
            self.writer.writerow(self.column_headers)
            return self

        def new_entry(self, entry: list):
            self.writer.writerow(entry)

        def __exit__(self, exc_type, exc_val, exc_tb):
            if self.file:
                self.file.close()
            self.writer = None

    def new_worksheet(self, workbook, worksheet_name: str, column_headers: list):
        """
        Creates a new CSV file (worksheet) in the workbook directory.
        Returns a context manager for writing to that file.
        :param workbook: The Path object for the workbook directory.
        :param worksheet_name: Base name for the CSV file.
        :param column_headers: List of column header strings.
        :return: A context manager for the CSV worksheet.
        """
        file_path = workbook / f"{worksheet_name}.csv"
        return self.CSVWorksheetContext(file_path, column_headers)

    def new_entry(self, worksheet, entry: list, format_list:list = []):
        """
        Appends a new row to the CSV file via its context manager.
        :param worksheet: The CSV worksheet context manager instance.
        :param entry: List of cell values.
        """
        worksheet.new_entry(entry)