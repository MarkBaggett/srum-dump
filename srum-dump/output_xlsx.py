from pathlib import Path
import xlsxwriter
import logging

# --- Logger Setup ---
logger = logging.getLogger(f"srum_dump.{__name__}")
# --- End Logger Setup ---

# Define valid number formats for cells with Excel-compatible formats
VALID_NUMBER_FORMATS = {
    "general": "General",
    "text": "@",
    "number": "#,##0.00",
    "integer": "#,##0",
    "percentage": "0.0000%",
    "date": "mm/dd/yyyy",
    "time": "hh:mm:ss",
    "datetime": "mm/dd/yyyy hh:mm"
}

# Define valid font colors.
FONT_COLORS = [
    "red",
    "blue",
    "yellow",
    "green"
]

class OutputXLSX:
    """
    A class for writing Excel workbooks using xlsxwriter.
    Each worksheet is managed by a context manager for efficient resource handling.
    Supports format styles for common formats (e.g., 'general-red', 'percentage-blue-bold') and 
    tuple-based formatting (e.g., ('percent', 'bold:red')) for flexibility.
    Highlight styles use the 'General' number format to display varied data types naturally.
    Handles bytes-to-string conversion and sets column widths based on header lengths.
    """
    def __init__(self):
        logger.debug("Initializing OutputXLSX.")
        self.wb = None
        self.path = None
        self.format_map = {}  # Store format objects for reuse
        logger.debug("OutputXLSX initialized.")

    def new_workbook(self, path: Path):
        """
        Creates a new Excel workbook and programmatically registers format styles for efficient writing.

        :param path: A pathlib.Path where the workbook will be saved.
        :return: An xlsxwriter Workbook.
        """
        logger.debug(f"Called new_workbook with path: {path}")
        try:
            #wb = xlsxwriter.Workbook(path.with_suffix(".xlsx"), {'remove_timezone': True})
            wb = xlsxwriter.Workbook(path.with_suffix(".xlsx"))
            self.path = path.with_suffix(".xlsx")
            self.wb = wb

            for num_format, excel_format in VALID_NUMBER_FORMATS.items():
                style_name = num_format
                fmt = wb.add_format({
                    'font_name': 'Calibri',
                    'font_size': 11,
                    'align': 'left',
                    'valign': 'top',
                    'text_wrap': True,
                    'num_format': excel_format
                })
                self.format_map[style_name] = fmt
                logger.debug(f"Registered style: {style_name} with format {excel_format}")

                for color in FONT_COLORS:
                    style_name = f"{num_format}-{color}"
                    fmt = wb.add_format({
                        'font_name': 'Calibri',
                        'font_size': 11,
                        'font_color': f"{color}",
                        'align': 'left',
                        'valign': 'top',
                        'text_wrap': True,
                        'num_format': excel_format
                    })
                    self.format_map[style_name] = fmt
                    logger.debug(f"Registered style: {style_name} with format {excel_format}")

                    style_name = f"{num_format}-{color}-bold"
                    fmt = wb.add_format({
                        'font_name': 'Calibri',
                        'font_size': 11,
                        'font_color': f"{color}",
                        'bold': True,
                        'align': 'left',
                        'valign': 'top',
                        'text_wrap': True,
                        'num_format': excel_format
                    })
                    self.format_map[style_name] = fmt
                    logger.debug(f"Registered style: {style_name} with format {excel_format}")

            highlight_combinations = [
                ('red', 'white'),
                ('yellow', 'black'),
                ('blue', 'white'),
                ('green', 'white'),
                ('purple', 'white')
            ]
            for bg_color, font_color in highlight_combinations:
                style_name = f"highlight-{bg_color}"
                fmt = wb.add_format({
                    'font_name': 'Calibri',
                    'font_size': 11,
                    'font_color': f"{font_color}",
                    'bg_color': f"{bg_color}",
                    'align': 'left',
                    'valign': 'top',
                    'text_wrap': True,
                    'num_format': "General"
                })
                self.format_map[style_name] = fmt
                logger.debug(f"Registered highlight style: {style_name} with format 'General'")

            logger.info(f"Created new workbook with {len(self.format_map)} format styles. Path set to: {self.path}")
            return wb
        except Exception as e:
            logger.exception(f"Error creating new workbook for path {path}: {e}")
            raise

    def save(self):
        """
        Closes and saves the current workbook to the path specified in new_workbook.
        """
        logger.debug(f"Called save for workbook path: {self.path}")
        if not self.wb or not self.path:
            err_msg = "Workbook or path not initialized. Call new_workbook first."
            logger.error(err_msg)
            raise Exception(err_msg)
        try:
            logger.info(f"Saving workbook to: {self.path}")
            self.wb.close()
            logger.info("Workbook saved successfully.")
        except Exception as e:
            logger.exception(f"Error saving workbook to {self.path}: {e}")
            raise

    class XLSXWorksheetContext:
        """Context manager for handling individual worksheets with headers and formatting."""
        def __init__(self, workbook, worksheet_name: str, column_headers: list, column_widths: list):
            self.logger = logging.getLogger(f"srum_dump.{__name__}.XLSXWorksheetContext")
            self.logger.debug(f"Initializing XLSXWorksheetContext for sheet: '{worksheet_name}'")
            if len(worksheet_name) > 31:
                err_msg = f"Truncating Worksheet name '{worksheet_name}' because it exceeds 31 characters."
                self.logger.error(err_msg)

            try:
                self.workbook = workbook
                self.worksheet_name = worksheet_name[:31]
                self.column_headers = column_headers
                self.column_widths = column_widths
                self.worksheet = None
                self.format_map = workbook.format_map
                logger.debug(f"Context initialized for sheet '{worksheet_name}' with {len(column_headers)} headers.")
            except Exception as e:
                self.logger.exception(f"Error during XLSXWorksheetContext initialization: {e}")
                raise

        def __enter__(self):
            """Creates the worksheet, sets up headers, and sets column widths based on header lengths."""
            self.logger.debug(f"Entering context for sheet: '{self.worksheet_name}'")
            try:
                self.logger.info(f"Creating sheet: '{self.worksheet_name}'")
                self.worksheet = self.workbook.add_worksheet(self.worksheet_name)
                self.logger.debug(f"Writing headers: {self.column_headers}")

                header_fmt = self.workbook.add_format({
                    'bold': True,
                    'align': 'center',
                    'valign': 'vcenter',
                    'border': 1
                })

                # Write headers and set column widths
                max_size = 100
                for col_idx, header in enumerate(self.column_headers):
                    if isinstance(header, bytes):
                        header = header.decode('utf-8', errors='replace')
                    self.worksheet.write(0, col_idx, header, header_fmt)
                    if self.column_widths[col_idx]:
                        width = self.column_widths[col_idx] + 2
                    width = min(width , max_size)  # Padding of 2, capped at max_size
                    self.worksheet.set_column(col_idx, col_idx, width)
                    self.logger.debug(f"Set width of column {col_idx} to {width} based on header '{header}'")

                self.worksheet.freeze_panes(1, 0)
                self.logger.debug("Froze header row (row 1).")

                if self.column_headers:
                    last_col = len(self.column_headers) - 1
                    self.worksheet.autofilter(0, 0, 0, last_col)
                    self.logger.debug(f"Set autofilter for columns 0 to {last_col}")
                else:
                    self.logger.warning("No column headers provided, skipping autofilter setup.")

                self.logger.debug(f"Worksheet '{self.worksheet_name}' setup complete.")
                return self.worksheet
            except Exception as e:
                self.logger.exception(f"Error during __enter__ for sheet '{self.worksheet_name}': {e}")
                self.worksheet = None
                raise

        def __exit__(self, exc_type, exc_val, exc_tb):
            """Cleans up upon exiting the context."""
            self.logger.debug(f"Exiting context for sheet: '{self.worksheet_name}'")
            try:
                self.logger.info(f"Completed operations on sheet: '{self.worksheet_name}'")
            except Exception as e:
                self.logger.exception(f"Error during exit: {str(e)}")
                raise

            if exc_type:
                self.logger.error(f"Exception occurred within worksheet context '{self.worksheet_name}': {exc_type.__name__}: {exc_val}", 
                                exc_info=(exc_type, exc_val, exc_tb))

            self.worksheet = None
            self.logger.debug(f"Worksheet reference cleared for '{self.worksheet_name}'.")

    def new_worksheet(self, workbook, worksheet_name: str, column_headers: list, column_widths: list):
        """
        Returns a context manager for a new worksheet in the given workbook.

        :param workbook: The xlsxwriter Workbook object.
        :param worksheet_name: Name for the worksheet (max 31 characters).
        :param column_headers: List of column header strings.
        :return: A context manager for the worksheet.
        """
        logger.debug(f"Creating new worksheet context for sheet: '{worksheet_name}'")
        if not isinstance(workbook, xlsxwriter.Workbook):
            err_msg = "Invalid workbook object provided to new_worksheet."
            logger.error(err_msg)
            raise TypeError(err_msg)
        if not isinstance(worksheet_name, str) or not worksheet_name:
            err_msg = "Worksheet name must be a non-empty string."
            logger.error(err_msg)
            raise ValueError(err_msg)
        if not isinstance(column_headers, list):
            err_msg = "Column headers must be a list."
            logger.error(err_msg)
            raise TypeError(err_msg)

        workbook.format_map = self.format_map
        return self.XLSXWorksheetContext(workbook, worksheet_name, column_headers, column_widths)

    def new_entry(self, worksheet, entry: list, format_options: list = None):
        """
        Appends a row of data to the given worksheet with formatting.
        Supports both tuple-based formatting (e.g., ('percent', 'bold:red')) and format styles
        (e.g., 'general-red', 'percent-blue-bold', 'highlight-yellow'). Highlight styles use
        the 'General' number format to display varied data types naturally.
        Converts bytes values to strings for xlsxwriter compatibility.

        :param worksheet: The worksheet object (as yielded by the context manager).
        :param entry: List of cell values (may contain bytes or strings).
        :param format_options: List of format specifiers (strings), same length as entry, or None.
        """
        format_options = format_options or []
        logger.debug(f"Called new_entry for sheet '{worksheet.name}' with {len(entry)} values. Format options provided: {bool(format_options)}")
        try:
            row_idx = worksheet._row_count if hasattr(worksheet, '_row_count') else 1
            worksheet._row_count = row_idx + 1

            for col_idx, (value, format_value) in enumerate(zip(entry, format_options + [None] * (len(entry) - len(format_options)))):
                if isinstance(value, bytes):
                    value = value.decode('utf-8', errors='replace')
                    logger.debug(f"Converted bytes to string for cell {row_idx},{col_idx}: {value}")

                if not format_value:
                    worksheet.write(row_idx, col_idx, value)
                    continue

                try:
                    if isinstance(format_value, str):
                        format_value = format_value.lower()
                        logger.debug(f"Processing format style for row {row_idx}, col {col_idx}: style='{format_value}'")
                        if format_value in self.format_map:
                            worksheet.write(row_idx, col_idx, value, self.format_map[format_value])
                            logger.debug(f"Applied format style '{format_value}' to cell {row_idx},{col_idx}")
                        else:
                            logger.warning(f"Invalid format style specified: '{format_value}' for cell {row_idx},{col_idx}. Writing without format.")
                            worksheet.write(row_idx, col_idx, value)
                    else:
                        logger.warning(f"Invalid format_value structure at row {row_idx}, col {col_idx}: {format_value}. Expected string. Writing without format.")
                        worksheet.write(row_idx, col_idx, value)

                except Exception as cell_format_ex:
                    logger.exception(f"Error applying format to cell at row {row_idx}, col {col_idx}: {cell_format_ex}")
                    worksheet.write(row_idx, col_idx, value)

            logger.debug(f"Appended entry to sheet '{worksheet.name}' at row {row_idx}.")
        except Exception as e:
            logger.exception(f"Error in new_entry for sheet '{worksheet.name}': {e}")
            raise