import tkinter as tk
import webbrowser
import pathlib
import os
import ctypes
import tempfile
import subprocess
import urllib.request
import pathlib
import sys
import logging # Added for logging

import helpers

from tkinter import ttk
from tkinter import filedialog, messagebox

from config_manager import ConfigManager

# --- Logger Setup ---
logger = logging.getLogger(f"srum_dump.{__name__}")
# --- End Logger Setup ---


# Determine base path for resources (like image)
if getattr(sys, 'frozen', False):
    base_path = sys._MEIPASS # Running in PyInstaller bundle
    logger.debug(f"Running frozen, base_path: {base_path}")
else:
    base_path = os.path.abspath(".") # Running as script
    logger.debug(f"Running as script, base_path: {base_path}")


icon_path = os.path.join(base_path, 'srum_dump.ico')
logger.debug(f"Icon path: {icon_path}")

class ProgressWindow:
    def __init__(self, title="SRUM Dump Progress"):
        logger.debug(f"Initializing ProgressWindow with title: {title}")
        try:
            self.root = tk.Tk()
            self.root.title(title)
            self.root.geometry("600x400")
            #self.root.attributes('-topmost', True) # Keep topmost initially?
            self.root.after(2000, self.remove_topmost, self.root)
            try:
                self.root.iconbitmap(icon_path)  # Replace with your icon file's path
            except tk.TclError:
                logger.exception("Icon file not found or invalid.")

            # Current table label
            self.table_label = tk.Label(self.root, text="Preparing to dump tables ...", font=('Arial', 10))
            self.table_label.pack(pady=5)

            # Progress bar frame
            progress_frame = tk.Frame(self.root)
            progress_frame.pack(fill=tk.X, padx=20, pady=5)

            self.progress_var = tk.DoubleVar()
            self.progress_bar = ttk.Progressbar(
                progress_frame,
                variable=self.progress_var,
                maximum=100
            )
            self.progress_bar.pack(fill=tk.X)

            # Stats frame
            stats_frame = tk.Frame(self.root)
            stats_frame.pack(fill=tk.X, padx=20, pady=5)

            # Records dumped
            self.records_var = tk.StringVar(value="Records Dumped: 0")
            self.records_label = tk.Label(stats_frame, textvariable=self.records_var)
            self.records_label.pack(side=tk.LEFT, padx=10)

            # Records per second
            self.rps_var = tk.StringVar(value="Records/sec: 0")
            self.rps_label = tk.Label(stats_frame, textvariable=self.rps_var)
            self.rps_label.pack(side=tk.RIGHT, padx=10)

            # Log text area
            log_frame = tk.Frame(self.root)
            log_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=5)

            # Scrollbar
            scrollbar = tk.Scrollbar(log_frame)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

            # Text widget
            self.log_text = tk.Text(log_frame, height=15, wrap=tk.WORD, yscrollcommand=scrollbar.set)
            self.log_text.pack(fill=tk.BOTH, expand=True)
            scrollbar.config(command=self.log_text.yview)

            # Close button frame
            button_frame = tk.Frame(self.root)
            button_frame.pack(fill=tk.X, padx=20, pady=5)

            # Close button - initially disabled
            self.close_button = tk.Button(
                button_frame,
                text="Close",
                command=self.close,
                state=tk.DISABLED  # Greyed out by default
            )
            self.close_button.pack(side=tk.RIGHT)

            self.total_tables = 0
            self.current_table = 0
            logger.debug("ProgressWindow initialized successfully.")
        except Exception as e:
            logger.exception(f"Error during ProgressWindow initialization: {e}")
            # Decide how to handle Tkinter init errors - maybe re-raise or exit?

    def start(self, total_tables):
        """Initialize the progress window with total number of tables"""
        logger.debug(f"Starting ProgressWindow with total_tables: {total_tables}")
        try:
            self.total_tables = total_tables
            self.current_table = 0
            self.progress_var.set(0)
            self.update()
            logger.debug("ProgressWindow started.")
        except Exception as e:
            logger.exception(f"Error in ProgressWindow start method: {e}")

    def remove_topmost(self, window):
        logger.debug("Called remove_topmost")
        try:
            if window and window.winfo_exists(): # Check if window exists
                window.attributes('-topmost', False)
                logger.debug("Removed topmost attribute.")
            else:
                logger.warning("Window does not exist in remove_topmost.")
        except Exception as e:
            logger.exception(f"Error removing topmost attribute: {e}")

    def set_current_table(self, table_name):
        """Update the current table being processed"""
        logger.debug(f"Setting current table to: {table_name}")
        try:
            self.current_table += 1
            self.table_label.config(text=f"Current Task: {table_name}")
            if self.total_tables > 0: # Avoid division by zero
                progress_percent = (self.current_table / self.total_tables) * 100
                self.progress_var.set(progress_percent)
                logger.debug(f"Progress set to {progress_percent:.2f}%")
            else:
                logger.warning("Total tables is 0, cannot calculate progress percentage.")
            self.update()
        except Exception as e:
            logger.exception(f"Error in set_current_table: {e}")

    def update_stats(self, records_dumped, records_per_second):
        """Update the statistics display"""
        logger.debug(f"Updating stats: records_dumped={records_dumped}, records_per_second={records_per_second}")
        try:
            self.records_var.set(f"Records Dumped: {records_dumped:,}")
            self.rps_var.set(f"Records/sec: {records_per_second:.1f}")
            self.update()
        except Exception as e:
            logger.exception(f"Error in update_stats: {e}")

    def log_message(self, message):
        """Add a message to the log window"""
        # Avoid logging every single message to prevent log spam,
        # but log the call itself for debugging UI flow.
        logger.debug(f"Called log_message (message length: {len(message)})")
        try:
            if self.log_text.winfo_exists(): # Check if text widget exists
                self.log_text.insert(tk.END, f"{message}\n")
                self.log_text.see(tk.END)  # Auto-scroll to bottom
                self.update()
            else:
                logger.warning("Log text widget does not exist in log_message.")
        except Exception as e:
            logger.exception(f"Error in log_message: {e}")

    def update(self):
        """Force window update"""
        logger.debug("Called update")
        try:
            if self.root and self.root.winfo_exists():
                self.root.update_idletasks()
                self.root.update()
                logger.debug("Window updated.")
            else:
                logger.warning("Root window does not exist in update.")
        except Exception as e:
            # Errors here can happen if the window is destroyed during update
            logger.warning(f"Error during UI update (might be expected during close): {e}")


    def hide_record_stats(self):
        """Hide the records stats labels"""
        logger.debug("Called hide_record_stats")
        try:
            if self.records_label.winfo_exists():
                self.records_label.pack_forget()
            if self.rps_label.winfo_exists():
                self.rps_label.pack_forget()
            logger.debug("Record stats hidden.")
        except Exception as e:
            logger.exception(f"Error in hide_record_stats: {e}")

    def finished(self):
        """Enable the close button when processing is complete"""
        logger.debug("Called finished")
        try:
            if self.close_button.winfo_exists():
                self.close_button.config(state=tk.NORMAL)  # Make button clickable
                logger.debug("Close button enabled.")
            else:
                logger.warning("Close button does not exist in finished.")
        except Exception as e:
            logger.exception(f"Error in finished method: {e}")

    def close(self):
        """Close the progress window"""
        logger.debug("Called close")
        try:
            if self.root and self.root.winfo_exists():
                self.root.destroy()
                logger.info("ProgressWindow closed.")
            else:
                logger.warning("Root window does not exist or already destroyed in close.")
        except Exception as e:
            logger.exception(f"Error closing ProgressWindow: {e}")


def error_message_box(title, message):
    logger.debug(f"Called error_message_box with title: {title}, message: {message[:50]}...")
    try:
        messagebox.showerror(title, message)
        logger.info(f"Displayed error message box with title: {title}")
    except Exception as e:
        logger.exception(f"Error displaying error message box: {e}")

def message_box(title, message):
    logger.debug(f"Called message_box with title: {title}, message: {message[:50]}...")
    try:
        messagebox.showinfo(title, message)
        logger.info(f"Displayed info message box with title: {title}")
    except Exception as e:
        logger.exception(f"Error displaying info message box: {e}")

def browse_file(initial_dir, filetypes):
    logger.debug(f"Called browse_file with initial_dir: {initial_dir}, filetypes: {filetypes}")
    file_path = ""
    root = None
    try:
        root = tk.Tk()
        root.withdraw()
        logger.debug("Temporary Tk root created and withdrawn.")
        resolved_initial_dir = str(pathlib.Path(initial_dir).resolve()).replace("/", "\\")
        logger.debug(f"Resolved initial directory: {resolved_initial_dir}")
        file_path = filedialog.askopenfilename(initialdir=resolved_initial_dir, filetypes=filetypes)
        logger.info(f"File dialog returned: {file_path}")
        # If a file was selected, canonicalize it and return with backslashes
        if file_path:
            canonical_path = str(pathlib.Path(file_path).resolve()).replace("/", "\\")
            logger.debug(f"Canonicalized path: {canonical_path}")
            return canonical_path
        else:
            logger.debug("No file selected.")
            return ""  # Return empty string if no file selected
    except Exception as e:
        logger.exception(f"Error in browse_file: {e}")
        return "" # Return empty on error
    finally:
        if root:
            try:
                root.destroy()
                logger.debug("Temporary Tk root destroyed.")
            except Exception as destroy_e:
                logger.warning(f"Error destroying temporary Tk root in browse_file: {destroy_e}")


def browse_directory(initial_dir):
    logger.debug(f"Called browse_directory with initial_dir: {initial_dir}")
    directory_path = ""
    root = None
    try:
        root = tk.Tk()
        root.withdraw()
        logger.debug("Temporary Tk root created and withdrawn.")
        resolved_initial_dir = str(pathlib.Path(initial_dir).resolve()).replace("/", "\\")
        logger.debug(f"Resolved initial directory: {resolved_initial_dir}")
        directory_path = filedialog.askdirectory(initialdir=resolved_initial_dir)
        logger.info(f"Directory dialog returned: {directory_path}")
        if directory_path:
            resolved_path = str(pathlib.Path(directory_path).resolve()).replace("/","\\")
            logger.debug(f"Resolved directory path: {resolved_path}")
            return resolved_path
        else:
            logger.debug("No directory selected.")
            return ""
    except Exception as e:
        logger.exception(f"Error in browse_directory: {e}")
        return "" # Return empty on error
    finally:
        if root:
            try:
                root.destroy()
                logger.debug("Temporary Tk root destroyed.")
            except Exception as destroy_e:
                logger.warning(f"Error destroying temporary Tk root in browse_directory: {destroy_e}")


def get_user_input(options):
    #Give the user the chance to change the options
    logger.debug(f"Called get_user_input with initial options: {options}")
    # Keep initial values for potential reset or comparison
    initial_out_dir = options.OUT_DIR
    initial_config_file = pathlib.Path(initial_out_dir).joinpath("srum_dump_config.json")

    # --- Nested Functions ---
    def edit_config():
        logger.debug("Called edit_config (nested in get_user_input)")
        try:
            config_path_str = initial_config_file
            logger.info(f"Attempting to edit config file: {config_path_str}")
            config_path = pathlib.Path(config_path_str)
            if not config_path.exists():
                logger.warning(f"Config file does not exist, creating empty file: {config_path}")
                config_path.touch() # Create empty file if it doesn't exist
            # Use os.startfile for default editor on Windows, more robust than assuming notepad.exe
            os.startfile(config_path)
            # subprocess.run(['notepad.exe', config_path_str]) # Less portable alternative
            logger.info(f"Opened config file for editing: {config_path_str}")
        except Exception as e:
            logger.exception(f"Error opening config file for editing: {e}")
            messagebox.showerror("Error", f"Could not open config file for editing:\n{e}")

    def on_support_click(event):
        logger.debug("Called on_support_click (nested in get_user_input)")
        try:
            twitter_url = "https://twitter.com/MarkBaggett"
            youtube_url = "http://youtube.com/markbaggett"
            logger.info(f"Opening support URL: {twitter_url}")
            webbrowser.open(twitter_url)
            logger.info(f"Opening support URL: {youtube_url}")
            webbrowser.open(youtube_url)
        except Exception as e:
            logger.exception(f"Error opening support links: {e}")

    def remove_topmost(window):
        logger.debug("Called remove_topmost (nested in get_user_input)")
        try:
            if window and window.winfo_exists():
                window.attributes('-topmost', False)
                logger.debug("Removed topmost attribute for main input window.")
            else:
                logger.warning("Main input window does not exist in remove_topmost.")
        except Exception as e:
            logger.exception(f"Error removing topmost attribute for main input window: {e}")

    def on_cancel():
            logger.debug("User clicked CANCEL. Existing program.")
            root.destroy()
            sys.exit(1)

    def on_confirm():
        logger.debug("Called on_ok (nested in get_user_input)")
        try:
            # Retrieve and resolve paths from entry fields
            out_dir_str = out_dir_entry.get()
            config_file_str = initial_config_file

            logger.debug(f"Raw paths from fields: OUT='{out_dir_str}'")

            out_dir = str(pathlib.Path(out_dir_str).resolve()).replace("/", "\\")

            # Validate paths
            valid = True
            if not pathlib.Path(out_dir).is_dir():
                logger.error(f"Validation failed: Output directory does not exist: {out_dir}")
                messagebox.showerror("Error", f"Output directory specified does not exist:\n{out_dir}")
                valid = False

            if valid:
                logger.info("Path validation successful.")
                # Update the options object passed into the function
                options.OUT_DIR = out_dir
                # options.CONFIG_FILE = config_file # Config file path isn't directly used in options object later
                logger.debug(f"Updated OUT_DIR option: {options}")
                root.destroy() # Close the window
                logger.debug("User Confirmation Window closed.")
            else:
                logger.warning("Validation failed, staying on input window.")
                return 

        except Exception as e:
            logger.exception(f"Error in on_ok handler: {e}")
            messagebox.showerror("Error", f"An unexpected error occurred:\n{e}")

    # --- Setup Main Window ---
    root = None
    try:
        root = tk.Tk()
        root.title("SRUM_DUMP 3.0")
        root.geometry("800x400")
        root.attributes('-topmost', True)
        root.after(20, remove_topmost , root)
        logger.debug("Main input window created.")
        try:
            root.iconbitmap(icon_path)  # Replace with your icon file's path
        except tk.TclError:
            logger.excpetion("Icon file not found or invalid.")

        image_path = os.path.join(base_path, 'srum-dump.png')
        logger.debug(f"Image path: {image_path}")

        # Logo
        logo_frame = tk.Frame(root, height=100, width=200)
        logo_frame.pack(pady=20)
        if pathlib.Path(image_path).is_file():
            logo_img = tk.PhotoImage(file=image_path)
            logo_label = tk.Label(logo_frame, image=logo_img)
            logo_label.image = logo_img  # Keep a reference!
            logo_label.pack()
            logger.debug("Logo image loaded.")
        else:
            tk.Label(logo_frame, text="SRUM DUMP Logo").pack() # Fallback text
            logger.warning(f"Logo image not found at: {image_path}")


        # Main content frame
        content_frame = tk.Frame(root)
        content_frame.pack(padx=20, fill=tk.BOTH, expand=True)

        # --- Input Fields ---

        # SRUM Database section
        # srum_frame = tk.LabelFrame(content_frame, text='REQUIRED: Path to SRUDB.DAT')
        # srum_frame.pack(fill=tk.X, pady=5, padx=5)
        # srum_input_frame = tk.Frame(srum_frame)
        # srum_input_frame.pack(fill=tk.X, padx=5, pady=5)
        # srum_path_entry = tk.Entry(srum_input_frame, width=80)
        # srum_path_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, pady=5)
        # srum_path_entry.insert(0, initial_srum_path)
        # tk.Button(srum_input_frame, text="Browse", command=lambda: srum_path_entry.delete(0, tk.END) or srum_path_entry.insert(0, browse_file(srum_path_entry.get() or initial_srum_path, [('SRUDB Database', 'srudb.dat'), ('All files', '*.*')]))).pack(side=tk.LEFT, padx=5)

        # Configuration File section
        config_frame = tk.LabelFrame(content_frame, text='Configuration File:')
        config_frame.pack(fill=tk.X, pady=5, padx=5)
        config_input_frame = tk.Frame(config_frame)
        config_input_frame.pack(fill=tk.X, padx=5, pady=5)
        config_file_label = tk.Label(config_input_frame, width=80, anchor=tk.W, bg="lightgray", relief=tk.SUNKEN)
        config_file_label.pack(side=tk.LEFT, expand=True, fill=tk.X, pady=5)
        config_file_label.config(text = initial_config_file)
        # config_file_entry = tk.Entry(config_input_frame, width=80)
        # config_file_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, pady=5)
        # config_file_entry.insert(0, str(initial_config_file)) # Use string representation
        #tk.Button(config_input_frame, text="Browse", command=lambda: config_file_entry.delete(0, tk.END) or config_file_entry.insert(0, browse_file(config_file_entry.get() or initial_out_dir, [('JSON Config', '*.json'), ('All files', '*.*')]))).pack(side=tk.LEFT, padx=5)
        tk.Button(config_input_frame, text="Edit", command=edit_config).pack(side=tk.LEFT, padx=5)

        # Output Directory section
        output_frame = tk.LabelFrame(content_frame, text='Output folder:')
        output_frame.pack(fill=tk.X, pady=5, padx=5)
        output_input_frame = tk.Frame(output_frame)
        output_input_frame.pack(fill=tk.X, padx=5, pady=5)
        # out_dir_label = tk.Label(output_input_frame, width=80, anchor=tk.W, bg="lightgray", relief=tk.SUNKEN) #added background and relief for better visual
        # out_dir_label.pack(side=tk.LEFT, expand=True, fill=tk.X, pady=5)
        # out_dir_label.config(text=initial_out_dir)
        out_dir_entry = tk.Entry(output_input_frame, width=80)
        out_dir_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, pady=5)
        out_dir_entry.insert(0, initial_out_dir)
        tk.Button(output_input_frame, text="Browse", command=lambda: out_dir_entry.delete(0, tk.END) or out_dir_entry.insert(0, browse_directory(out_dir_entry.get() or initial_out_dir))).pack(side=tk.LEFT, padx=5)

        # Support link
        support_label = tk.Label(root, text="Click here for support via Twitter @MarkBaggett",
                               fg="blue", cursor="hand2")
        support_label.pack(pady=10)
        support_label.bind("<Button-1>", on_support_click)

        # Action buttons
        button_frame = tk.Frame(root)
        button_frame.pack(pady=10)
        tk.Button(button_frame, text="Confirm", command=on_confirm, width=10).pack(side=tk.LEFT, padx=10)
        tk.Button(button_frame, text="Cancel", command=on_cancel, width=10).pack(side=tk.LEFT, padx=10)

        logger.debug("Starting main input window mainloop.")
        root.mainloop()
        logger.debug("Main input window mainloop finished.")

    except Exception as e:
        logger.exception(f"Error setting up or running get_user_input main window: {e}")
        # Optionally show an error message if Tkinter setup fails critically
        try:
            messagebox.showerror("Fatal Error", f"Could not initialize the main input window:\n{e}")
        except:
            logger.exception(f"FATAL ERROR: Could not initialize the main input window: {e}", file=sys.stderr)
        # Decide whether to exit or try to continue
        sys.exit(1) # Exit if UI fails critically

    logger.debug("Exiting get_user_input function.")
    # Options object is modified in place by on_ok


def get_input_wizard(options):
    logger.debug(f"Called get_input_wizard with initial options: {options}")
    cwd = os.getcwd()
    logger.debug(f"Current working directory: {cwd}")

    # --- Nested Step Window Function ---
    def create_step_window(title, label_text, default_value, starting_location, filetypes, next_label='Next..'):
        logger.debug(f"Creating step window: title='{title}', label='{label_text}', default='{default_value}', start_loc='{starting_location}', filetypes='{filetypes}', next_label='{next_label}'")
        result = "" # Initialize result
        window = None

        # --- Nested Event Handlers ---
        def on_browse():
            logger.debug("Browse button clicked.")
            browse_result = ""
            try:
                current_start = starting_location or os.getcwd() # Fallback starting location
                if filetypes != 'dir':
                    logger.debug(f"Calling browse_file with start: {current_start}, types: {filetypes}")
                    browse_result = browse_file(current_start, filetypes)
                else:
                    logger.debug(f"Calling browse_directory with start: {current_start}")
                    browse_result = browse_directory(current_start)

                if browse_result:
                    logger.info(f"Browse result: {browse_result}")
                    path_entry.delete(0, tk.END)
                    path_entry.insert(0, browse_result)
                else:
                    logger.debug("Browse cancelled or returned empty.")
            except Exception as browse_e:
                logger.exception(f"Error during browse operation: {browse_e}")
                messagebox.showerror("Browse Error", f"An error occurred during browsing:\n{browse_e}")

        def on_next():
            logger.debug("Next/Finish button clicked.")
            window.quit() # End the window's mainloop

        def remove_topmost(win): # Renamed parameter to avoid conflict
            logger.debug("Removing topmost for step window.")
            try:
                if win and win.winfo_exists():
                    win.attributes('-topmost', False)
                    logger.debug("Removed topmost attribute for step window.")
                else:
                     logger.warning("Step window does not exist in remove_topmost.")
            except Exception as e:
                logger.exception(f"Error removing topmost for step window: {e}")

        def on_exit():
            logger.warning("Exit button clicked.")
            path_entry.delete(0, tk.END)
            path_entry.insert(0,'EXIT') # Special value to signal exit
            window.quit() # End the window's mainloop

        # --- Setup Step Window ---
        try:
            window = tk.Tk()
            window.title(title)
            window.geometry("600x150+300+200") # Position might need adjustment
            window.attributes('-topmost', True)
            window.after(2000, remove_topmost, window) # Pass window object
            logger.debug(f"Step window '{title}' created.")
            try:
                window.iconbitmap(icon_path)  # Replace with your icon file's path
            except tk.TclError:
                logger.exception("Icon file not found or invalid.")

            frame = tk.Frame(window)
            frame.pack(pady=20, padx=20, fill=tk.X)

            tk.Label(frame, text=label_text).pack(anchor='w')

            path_entry = tk.Entry(frame, width=60)
            path_entry.insert(0, str(default_value)) # Ensure default is string
            path_entry.pack(pady=5, fill=tk.X)

            button_frame = tk.Frame(window)
            button_frame.pack(pady=10)

            tk.Button(button_frame, text="Browse", command=on_browse).pack(side=tk.LEFT, padx=10)
            tk.Button(button_frame, text=next_label, command=on_next).pack(side=tk.LEFT, padx=10)
            tk.Button(button_frame, text="Exit", command=on_exit).pack(side=tk.RIGHT, padx=10)

            logger.debug(f"Starting mainloop for step window '{title}'.")
            window.mainloop()
            logger.debug(f"Mainloop finished for step window '{title}'.")

            result = path_entry.get() # Get result after mainloop finishes
            logger.debug(f"Result from step window '{title}': {result}")

        except Exception as e:
            logger.exception(f"Error creating or running step window '{title}': {e}")
            result = "ERROR" # Indicate error
        finally:
            if window:
                try:
                    window.destroy()
                    logger.debug(f"Step window '{title}' destroyed.")
                except Exception as destroy_e:
                    logger.warning(f"Error destroying step window '{title}': {destroy_e}")
        return result

    # --- Wizard Logic ---
    try:
        # Step 1: Get Working directory
        logger.info("Starting Wizard Step 1: Output Directory")
        working_default = pathlib.Path().home()
        output_dir = ""
        while True:
            output_dir = create_step_window(
                "Step 1: Select Output/Working Directory",
                "Select a directory for output, artifacts, logs, etc:",
                working_default, # default value
                working_default, # starting browse location
                'dir'            # 'dir' indicates directory selection
            )
            if output_dir == 'EXIT':
                logger.warning("User chose to exit during Step 1.")
                sys.exit(1)
            elif output_dir == "ERROR":
                 logger.error("Error occurred in Step 1 window. Exiting.")
                 sys.exit(1)
            elif pathlib.Path(output_dir).is_dir():
                logger.info(f"Output directory selected: {output_dir}")
                break
            else:
                logger.warning(f"Invalid directory selected: {output_dir}")
                messagebox.showerror("Invalid Directory", f"The selected path is not a valid directory:\n{output_dir}")
                working_default = output_dir # Keep invalid path as default for next try

        # Check for existing config to pre-fill SRUM path
        config_path = pathlib.Path(output_dir).joinpath("srum_dump_config.json")
        infile = None
        if config_path.is_file():
            logger.info(f"Existing config file found: {config_path}")
            try:
                # Use ConfigManager to safely read the config
                cfg_mgr = ConfigManager(config_path)
                defaults = cfg_mgr.get_config("defaults")
                if defaults:
                    infile = defaults.get("SRUM_INFILE")
                    if infile:
                         logger.debug(f"Found previous SRUM_INFILE in config: {infile}")
            except Exception as cfg_read_e:
                 logger.warning(f"Could not read SRUM_INFILE from existing config {config_path}: {cfg_read_e}")
        else:
             logger.debug(f"No existing config file found at {config_path}")


        # Step 2: Get SRUM path
        logger.info("Starting Wizard Step 2: SRUM Database Path")
        srum_default = ""
        srum_location = output_dir # Default browse location
        # Determine default SRUM path based on priority
        if infile and pathlib.Path(infile).is_file():
            srum_default = infile
            srum_location = pathlib.Path(infile).parent # Start browse near existing file
            logger.debug(f"Using SRUM default from config: {srum_default}")
        elif pathlib.Path(output_dir).joinpath('SRUDB.dat').is_file():
            srum_default = pathlib.Path(output_dir).joinpath('SRUDB.dat')
            srum_location = output_dir
            logger.debug(f"Using SRUM default from output dir: {srum_default}")
        elif pathlib.Path.cwd().joinpath('SRUDB.dat').is_file():
            srum_default = pathlib.Path.cwd().joinpath('SRUDB.dat')
            srum_location = pathlib.Path.cwd()
            logger.debug(f"Using SRUM default from current dir: {srum_default}")
        else:
            srum_default = pathlib.Path("c:/windows/system32/sru/srudb.dat") # Live system default
            srum_location = srum_default.parent
            logger.debug(f"Using SRUM default for live system: {srum_default}")

        srum_path = ""
        while True:
            srum_path = create_step_window(
                "Step 2: Select SRUM Database",
                "Select the SRUDB.dat file to analyze:",
                str(srum_default),
                str(srum_location),
                [('SRUM Database', 'srudb.dat'), ('All files', '*.*')]
            )
            if srum_path == 'EXIT':
                logger.warning("User chose to exit during Step 2.")
                sys.exit(1)
            elif srum_path == "ERROR":
                 logger.error("Error occurred in Step 2 window. Exiting.")
                 sys.exit(1)
            elif pathlib.Path(srum_path).is_file():
                logger.info(f"SRUM database selected: {srum_path}")
                break
            else:
                logger.warning(f"Invalid SRUM path selected: {srum_path}")
                messagebox.showerror("Invalid File", f"The selected path is not a valid file:\n{srum_path}")
                srum_default = srum_path # Keep invalid path as default

        # Step 3: Get SOFTWARE hive path (Optional)
        logger.info("Starting Wizard Step 3: SOFTWARE Hive Path (Optional)")
        software_default = ''
        software_location = pathlib.Path(srum_path).parent # Start browse near SRUM DB
        # Determine default SOFTWARE path
        if pathlib.Path(output_dir).joinpath('SOFTWARE').is_file():
            software_default = pathlib.Path(output_dir).joinpath('SOFTWARE')
            software_location = output_dir
            logger.debug(f"Using SOFTWARE default from output dir: {software_default}")
        elif pathlib.Path(srum_path).parent.joinpath('SOFTWARE').is_file():
            software_default = pathlib.Path(srum_path).parent.joinpath('SOFTWARE')
            logger.debug(f"Using SOFTWARE default from SRUM dir: {software_default}")
        elif pathlib.Path(srum_path).parent.parent.joinpath('config/SOFTWARE').is_file(): # Check common ..\config structure
            software_default = pathlib.Path(srum_path).parent.parent.joinpath('config/SOFTWARE')
            software_location = software_default.parent
            logger.debug(f"Using SOFTWARE default from ../config dir: {software_default}")
        else:
             logger.debug("No default SOFTWARE hive found.")


        software_path = ""
        while True:
            software_path = create_step_window(
                "Step 3: Select SOFTWARE Hive (Optional)",
                "Optionally, select the corresponding SOFTWARE registry hive:",
                str(software_default),
                str(software_location),
                [('SOFTWARE Hive', 'SOFTWARE'), ('Registry Hives', '*'), ('All files', '*.*')],
                "Finish" # Change button label for last step
            )
            if software_path == 'EXIT':
                logger.warning("User chose to exit during Step 3.")
                sys.exit(1)
            elif software_path == "ERROR":
                 logger.error("Error occurred in Step 3 window. Exiting.")
                 sys.exit(1)
            # Allow empty path, but validate if a path is provided
            elif software_path == '' or pathlib.Path(software_path).is_file():
                if software_path:
                    logger.info(f"SOFTWARE hive selected: {software_path}")
                else:
                    logger.info("No SOFTWARE hive selected (optional step).")
                break
            else:
                logger.warning(f"Invalid SOFTWARE path selected: {software_path}")
                messagebox.showerror("Invalid File", f"The selected path is not a valid file (or leave blank):\n{software_path}")
                software_default = software_path # Keep invalid path as default

        # Update options object (passed by reference)
        options.SRUM_INFILE = str(pathlib.Path(srum_path).resolve()) # Resolve paths
        options.REG_HIVE = str(pathlib.Path(software_path).resolve()) if software_path else ''
        options.OUT_DIR = str(pathlib.Path(output_dir).resolve())

        logger.info(f"Wizard finished. Final options set: SRUM='{options.SRUM_INFILE}', REG='{options.REG_HIVE}', OUT='{options.OUT_DIR}'")
        return options

    except Exception as wizard_e:
        logger.exception(f"An unexpected error occurred during the input wizard: {wizard_e}")
        messagebox.showerror("Wizard Error", f"An unexpected error occurred during setup:\n{wizard_e}")
        sys.exit(1) # Exit on critical wizard failure
