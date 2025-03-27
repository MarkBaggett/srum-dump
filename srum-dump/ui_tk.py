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

import helpers

from tkinter import ttk
from tkinter import filedialog, messagebox

from config_manager import ConfigManager

class ProgressWindow:
    def __init__(self, title="SRUM Dump Progress"):
        self.root = tk.Tk()
        self.root.title(title)
        self.root.geometry("600x400")
        #self.root.attributes('-topmost', True)
        self.root.after(2000, self.remove_topmost, self.root)
        
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

    def start(self, total_tables):
        """Initialize the progress window with total number of tables"""
        self.total_tables = total_tables
        self.current_table = 0
        self.progress_var.set(0)
        self.update()

    def remove_topmost(self, window):
        window.attributes('-topmost', False)

    def set_current_table(self, table_name):
        """Update the current table being processed"""
        self.current_table += 1
        self.table_label.config(text=f"Current Task: {table_name}")
        self.progress_var.set((self.current_table / self.total_tables) * 100)
        self.update()

    def update_stats(self, records_dumped, records_per_second):
        """Update the statistics display"""
        self.records_var.set(f"Records Dumped: {records_dumped:,}")
        self.rps_var.set(f"Records/sec: {records_per_second:.1f}")
        self.update()

    def log_message(self, message):
        """Add a message to the log window"""
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)  # Auto-scroll to bottom
        self.update()

    def update(self):
        """Force window update"""
        self.root.update_idletasks()
        self.root.update()

    def hide_record_stats(self):
        """Hide the records stats labels"""
        self.records_label.pack_forget()
        self.rps_label.pack_forget()

    def finished(self):
        """Enable the close button when processing is complete"""
        self.close_button.config(state=tk.NORMAL)  # Make button clickable

    def close(self):
        """Close the progress window"""
        self.root.destroy()


def error_message_box(title, message):
    messagebox.showerror(title, message)

def message_box(title, message):
    messagebox.showinfo(title, message)

def browse_file(initial_dir, filetypes):
    root = tk.Tk()
    root.withdraw()
    initial_dir = str(pathlib.Path(initial_dir).resolve()).replace("/", "\\")
    file_path = filedialog.askopenfilename(initialdir=initial_dir, filetypes=filetypes)
    root.destroy()
    # If a file was selected, canonicalize it and return with backslashes
    if file_path:
        canonical_path = str(pathlib.Path(file_path).resolve()).replace("/", "\\")
        return canonical_path
    return ""  # Return empty string if no file selected

def browse_directory(initial_dir):
    root = tk.Tk()
    root.withdraw()
    initial_dir = str(pathlib.Path(initial_dir).resolve()).replace("/", "\\")
    directory_path = filedialog.askdirectory(initialdir=initial_dir)
    root.destroy()
    return str(pathlib.Path(directory_path).resolve()).replace("/","\\")

def get_user_input(options):
    srum_path = options.SRUM_INFILE
    config_file = pathlib.Path(options.OUT_DIR).joinpath("srum_dump_config.json")
    out_dir = options.OUT_DIR

    def edit_config():
        config_path = config_file_entry.get()
        if not pathlib.Path(config_path).exists():
            # Create empty file if it doesn't exist
            pathlib.Path(config_path).touch()
        subprocess.run(['notepad.exe', config_path])

    def on_support_click(event):
        webbrowser.open("https://twitter.com/MarkBaggett")
        webbrowser.open("http://youtube.com/markbaggett")

    def remove_topmost( window):
        window.attributes('-topmost', False)

    def on_ok():
        srum_path = str(pathlib.Path(srum_path_entry.get()).resolve()).replace("/","\\")
        out_dir = str(pathlib.Path(out_dir_entry.get()).resolve()).replace("/", "\\")
        config_file = str(pathlib.Path(config_file_entry.get()).resolve()).replace("/", "\\")

        if not pathlib.Path(srum_path).is_file():
            messagebox.showerror("Error", "The SRUM database specified does not exist.")
            return
        if not pathlib.Path(out_dir).is_dir():
            messagebox.showerror("Error", "Output directory specified does not exist.")
            return
        if  not pathlib.Path(config_file).is_file():
            messagebox.showerror("Error", "Config file specified does not exist.")
            return

        options.SRUM_INFILE = srum_path
        options.OUT_DIR = out_dir
        options.CONFIG_FILE = config_file
        root.destroy()

    root = tk.Tk()
    root.title("SRUM_DUMP 3.0")
    root.geometry("800x500")
    root.attributes('-topmost', True)
    root.after(2000, remove_topmost , root)

    # Get the correct path to the image
    if getattr(sys, 'frozen', False):
        # Running in a PyInstaller bundle
        base_path = sys._MEIPASS
    else:
        # Running in a normal Python environment
        base_path = os.path.abspath(".")

    image_path = os.path.join(base_path, 'srum-dump.png')

    # Logo placeholder frame at the top
    logo_frame = tk.Frame(root, height=100, width=200)
    logo_frame.pack(pady=20)
    # Placeholder for logo - replace 'logo.png' with your image
    logo_img = tk.PhotoImage(file=image_path)
    logo_label = tk.Label(logo_frame, image=logo_img)
    logo_label.image = logo_img  # Keep a reference
    logo_label.pack()

    # Main content frame
    content_frame = tk.Frame(root)
    content_frame.pack(padx=20, fill=tk.BOTH, expand=True)

    # SRUM Database section
    srum_frame = tk.Frame(content_frame)
    srum_frame.pack(fill=tk.X, pady=10)
    tk.Label(srum_frame, text='REQUIRED: Path to SRUDB.DAT').pack(anchor='w')
    srum_input_frame = tk.Frame(srum_frame)
    srum_input_frame.pack(fill=tk.X)
    srum_path_entry = tk.Entry(srum_input_frame, width=80)
    srum_path_entry.pack(side=tk.LEFT, pady=5)
    srum_path_entry.insert(0, srum_path)
    tk.Button(srum_input_frame, text="Browse", command=lambda: browse_file(options.SRUM_INFILE, [('SRUDB.dat', 'srudb.dat'), ('All files', '*.*')])).pack(side=tk.LEFT, padx=5)

    # Configuration File section
    config_frame = tk.Frame(content_frame)
    config_frame.pack(fill=tk.X, pady=10)
    tk.Label(config_frame, text='REQUIRED: Configuration File (with data from SOFTWARE)').pack(anchor='w')
    config_input_frame = tk.Frame(config_frame)
    config_input_frame.pack(fill=tk.X)
    config_file_entry = tk.Entry(config_input_frame, width=80)
    config_file_entry.pack(side=tk.LEFT, pady=5)
    config_file_entry.insert(0, config_file)
    tk.Button(config_input_frame, text="Browse", command=lambda: browse_file(options.OUT_DIR, [('config file','*.json')])).pack(side=tk.LEFT, padx=5)
    tk.Button(config_input_frame, text="Edit", command=edit_config).pack(side=tk.LEFT, padx=5)

    # Output Directory section
    output_frame = tk.Frame(content_frame)
    output_frame.pack(fill=tk.X, pady=10)
    tk.Label(output_frame, text='REQUIRED: Output folder for SRUM_DUMP_OUTPUT.xlsx').pack(anchor='w')
    output_input_frame = tk.Frame(output_frame)
    output_input_frame.pack(fill=tk.X)
    out_dir_entry = tk.Entry(output_input_frame, width=80)
    out_dir_entry.pack(side=tk.LEFT, pady=5)
    out_dir_entry.insert(0, out_dir)
    tk.Button(output_input_frame, text="Browse", command=lambda: browse_directory(out_dir)).pack(side=tk.LEFT, padx=5)

    # Support link at bottom
    support_label = tk.Label(root, text="Click here for support via Twitter @MarkBaggett", 
                           fg="blue", cursor="hand2")
    support_label.pack(pady=20)
    support_label.bind("<Button-1>", on_support_click)

    # Action buttons at bottom
    button_frame = tk.Frame(root)
    button_frame.pack(pady=20)
    tk.Button(button_frame, text="Confirm", command=on_ok).pack(side=tk.LEFT, padx=5)
    tk.Button(button_frame, text="Cancel", command=root.destroy).pack(side=tk.LEFT, padx=5)

    root.mainloop()


def get_input_wizard(options):
    cwd = os.getcwd()

    def create_step_window(title, label_text, default_value, starting_location, filetypes, next_label='Next..'):
        def on_browse():
            if filetypes != 'dir':
                result = browse_file(starting_location, filetypes)
            else:
                result = browse_directory(starting_location)
            if result:
                path_entry.delete(0, tk.END)
                path_entry.insert(0, result)

        def on_next():
            window.quit()

        def remove_topmost(window):
            window.attributes('-topmost', False)

        def on_exit():
            path_entry.delete(0, tk.END)
            path_entry.insert(0,'EXIT')
            window.quit()

        window = tk.Tk()
        window.title(title)
        window.geometry("600x150+300+200")
        window.attributes('-topmost', True)
        window.after(2000, remove_topmost, window)

        frame = tk.Frame(window)
        frame.pack(pady=20)

        tk.Label(frame, text=label_text).pack()
        
        path_entry = tk.Entry(frame, width=60)
        path_entry.insert(0, default_value)
        path_entry.pack(pady=10)

        button_frame = tk.Frame(window)
        button_frame.pack(pady=10)


        tk.Button(button_frame, text="Browse", command=on_browse).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text=next_label, command=on_next).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Exit", command=on_exit).pack(side=tk.RIGHT, padx=90)

        window.mainloop()
        result = path_entry.get()  # Store the result before destroying the window
        window.destroy()  # Explicitly destroy the window
        return result
    
    # Step 1: Get Working directory
    working_default = pathlib.Path().home() 
    while True:
        output_dir = create_step_window(
            "Step 1: Select Output/Working Directory",
            "Click browse and select or type a directory for output and confiuration files",
            working_default, #default value
            working_default, #starting browse location
            'dir'  # 'dir' is a special value to indicate a directory selection
        )
        if output_dir == 'EXIT':
            sys.exit(1)
        elif pathlib.Path(output_dir).is_dir():
            break
        else:
            messagebox.showerror("Error", "You must select a valid directory.")

    #check to see if a config exists so we can use the previous directories.
    config_path = pathlib.Path(output_dir).joinpath("srum_dump_config.json")
    if config_path.is_file():
        infile = ConfigManager(config_path).get_config("defaults").get("SRUM_INFILE")
    else:
        infile = None

    # Step 2: Get SRUM path
    if infile and pathlib.Path(infile):
        srum_default = infile
        srum_location = infile
    elif pathlib.Path().cwd().joinpath('SRUDB.dat').exists():  #next current directory
        srum_default = pathlib.Path().cwd().joinpath('SRUDB.dat')
        srum_location = srum_default.parent
    elif pathlib.Path(output_dir).joinpath('SRUDB.dat').exists():  #maybe they are all in outfile
        srum_default = pathlib.Path(output_dir).joinpath('SRUDB.dat')
        srum_location = srum_default.parent
    else:                                                           #last default to live system
        srum_default = pathlib.Path("c:/windows/system32/sru/srudb.dat")
        srum_location = pathlib.Path(output_dir) 
    while True: 
        srum_path = create_step_window(
            "Step 2: Select SRUM Database",
            "Click Browse and select or type a valid path to SRUDB.dat:",
            str(srum_default),
            srum_location,
            [('SRUDB.dat', 'srudb.dat'), ('All files', '*.*')]
        ) 
        if srum_path == 'EXIT':
            sys.exit(1)
        elif os.path.exists(pathlib.Path(srum_path)):
            break
        else:
            messagebox.showerror("Error", "You must select a valid SRUM Datbase (srudb.dat).")
        
    
    # Step 2: Get SOFTWARE file
    if pathlib.Path(output_dir).joinpath('SOFTWARE').exists():
        software_default = pathlib.Path(output_dir).joinpath('SOFTWARE')
        software_location = software_default.parent
    elif pathlib.Path(srum_path).parent.joinpath('SOFTWARE').exists():
        software_default = pathlib.Path(srum_path).parent.joinpath('SOFTWARE')
        software_location = software_default.parent
    elif pathlib.Path(srum_path).parent.parent.joinpath('config/SOFTWARE').exists():    
        software_default = pathlib.Path(srum_path).parent.parent.joinpath('config/SOFTWARE')
        software_location = software_default
    else: 
        software_default = ''
        software_location = pathlib.Path(srum_path).parent
    while True:
        software_path = create_step_window(
            "Step 3: OPTIONALLY select a SOFTWARE Hive",
            "Leave this blank OR select/enter the associated SOFTWARE hive:",
            str(software_default),
            software_location,
            [('SOFTWARE', 'SOFTWARE'), ('All files', '*.*')],
            "Finish"
        )
        if software_path == 'EXIT': 
            sys.exit(1)
        if software_path != '' and not os.path.exists(pathlib.Path(software_path)):
            messagebox.showerror("Error", "You must select a valid SOFTWARE hive or leave the field empty.")
        else:
            break


    # Update options dictionary
    options.SRUM_INFILE = srum_path
    options.REG_HIVE = software_path if software_path else ''
    options.OUT_DIR = output_dir if output_dir else cwd

    return options