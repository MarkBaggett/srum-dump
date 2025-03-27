from pathlib import Path
import openpyxl

from openpyxl.styles import Font
from openpyxl.cell import WriteOnlyCell, Cell
from openpyxl.utils import get_column_letter

# Define valid number formats for cells
VALID_NUMBER_FORMATS = {
    "General": "General",
    "Text": "@",
    "Number": "#,##0.00",
    "Integer": "#,##0",
    "Percentage": "0.00%",
    "Scientific": "0.00E+00",
    "Currency": '"$"#,##0.00',
    "Euro": '"€"#,##0.00',
    "Short Date": "MM/DD/YYYY",
    "Long Date": "DD-MMM-YYYY",
    "Time": "HH:MM:SS",
    "DateTime": "MM/DD/YYYY HH:MM"
}

# Define valid font colors (Excel requires aRGB hex values)
VALID_FONT_COLORS = {
    "BLACK": "FF000000",
    "WHITE": "FFFFFFFF",
    "RED": "FFFF0000",
    "GREEN": "FF00FF00",
    "BLUE": "FF0000FF",
    "YELLOW": "FFFFFF00",
    "CYAN": "FF00FFFF",
    "MAGENTA": "FFFF00FF",
    "GRAY": "FF808080",
    "DARKRED": "FF8B0000",
    "DARKGREEN": "FF006400",
    "DARKBLUE": "FF00008B",
    "DARKYELLOW": "FF9B870C",
    "DARKCYAN": "FF008B8B",
    "DARKMAGENTA": "FF8B008B",
    "DARKGRAY": "FFA9A9A9",
    "LIGHTGRAY": "FFD3D3D3"
}

class OutputXLSX:
    """
    A class for writing Excel workbooks using openpyxl in write-only mode.
    Each worksheet is managed by a context manager.
    """
    def __init__(self):
        self.wb = None
        self.path = None

    def new_workbook(self, path: Path):
        """
        Creates a new write-only Excel workbook.
        The caller is responsible for calling workbook.save(path) after
        writing all worksheets.
        
        :param path: A pathlib.Path where the workbook will eventually be saved.
        :return: An openpyxl Workbook (in write_only mode).
        """
        # Create workbook
        wb = openpyxl.Workbook()
        self.path = path.with_suffix(".xlsx")
        self.wb = wb
        return wb
    
    def save(self):
        self.wb.save(self.path)
        

    class XLSXWorksheetContext:
        def __init__(self, workbook, worksheet_name: str, column_headers: list):
            self.workbook = workbook
            self.worksheet_name = worksheet_name
            self.column_headers = column_headers
            self.worksheet = None

        def __enter__(self):
            # Create a new worksheet and write the header row.
            self.worksheet = self.workbook.create_sheet(title=self.worksheet_name)
            self.worksheet.append(self.column_headers)

            # Bold first row
            for col_idx, _ in enumerate(self.column_headers, start=1):
                cell = self.worksheet[f"{get_column_letter(col_idx)}1"]
                cell.font = Font(bold=True)

            # Freeze first row
            self.worksheet.freeze_panes = "A2"

            # Set AutoFilter for all columns (only header row)
            last_col = get_column_letter(len(self.column_headers))
            self.worksheet.auto_filter.ref = f"A1:{last_col}1"  # Filter applies based on header row

            return self.worksheet

        def __exit__(self, exc_type, exc_val, exc_tb):
            # No explicit close exists for openpyxl worksheets;
            # we remove our reference to free memory.
            self.worksheet = None

    def new_worksheet(self, workbook, worksheet_name: str, column_headers: list):
        """
        Returns a context manager for a new worksheet in the given workbook.
        Usage:
            with instance.new_worksheet(workbook, "Sheet1", headers) as ws:
                instance.new_entry(ws, row)
                ...
        :param workbook: The openpyxl Workbook object.
        :param worksheet_name: Name for the worksheet.
        :param column_headers: List of column header strings.
        :return: A context manager for the worksheet.
        """
        return self.XLSXWorksheetContext(workbook, worksheet_name, column_headers)
    

    def new_entry(self, worksheet, entry: list, format_options: list = []):
        """
        Appends a row of data to the given worksheet with formatting.
        
        :param worksheet: The worksheet object (as yielded by the context manager).
        :param entry: List of cell values.
        :param format_options: List of tuples (cell_format, font_format), same length as entry.
        """
        # Write data to worksheet
        worksheet.append(entry)  # This is faster than setting each cell individually

        #If no formatting specified we are done (speed optimization)
        if not any(format_options):
            return

        # Get the row index of the newly added row (max_row gives the row where data was added)
        row_idx = worksheet.max_row

        # Apply number format in bulk
        for idx, format_value in enumerate(format_options, start=1):
            if not format_value:  #Punch out if no format specified for this cell
                continue
            
            cell_format, font_format = format_value
            # Get the cell reference
            cell = worksheet.cell(row=row_idx, column=idx)

            # Validate and apply cell format
            if cell_format:
                assert cell_format in VALID_NUMBER_FORMATS, f"Invalid cell format: {cell_format}"
                cell.number_format = VALID_NUMBER_FORMATS[cell_format]

            # Apply font formatting to the specific cell
            if font_format:
                font_parts = font_format.split(":")
                font_style = font_parts[0]  # "BOLD" or "NORMAL"
                font_color = font_parts[1].upper() if len(font_parts) > 1 else "BLACK"  # Default to black

                # Validate font color
                assert font_color in VALID_FONT_COLORS, f"Invalid font color: {font_color}"

                # Apply the font style and color to the specific cell
                cell.font = Font(
                    bold=(font_style == "BOLD"),
                    color=VALID_FONT_COLORS[font_color]  # Convert color name to hex
                )