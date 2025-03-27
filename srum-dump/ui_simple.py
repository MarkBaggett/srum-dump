import PySimpleGUI as sg
import webbrowser
import pathlib
import os
import ctypes
import tempfile
import subprocess
import urllib.request

def show_live_system_warning():
    """Warn the user when they try to analyze the srum on their own live system."""
    layout = [
        [sg.Text("It appears you're trying to open SRUDB.DAT from a live system.")],
        [sg.Text("Copying or reading that file while it is locked is unlikely to succeed.")],
        [sg.Text("First, use a tool such as FGET that can copy files that are in use.")],
        [sg.Text(r"Try: 'fget -extract c:\windows\system32\sru\srudb.dat <a destination path>'")],
        [sg.Button("Close"), sg.Button("Download FGET")]
    ]
    if ctypes.windll.shell32.IsUserAnAdmin() == 1:
        layout[-1].append(sg.Button("Auto Extract"))
    pop_window = sg.Window("WARNING", layout, no_titlebar=True, keep_on_top=True, border_depth=5)
    return_value = None
    while True:
        event, _ = pop_window.Read()
        if event in (None, "Close"):
            break
        if event == "Download FGET":
            webbrowser.open("https://github.com/MarkBaggett/srum-dump/blob/master/FGET.exe")
        if event == "Auto Extract":
            return_value = extract_live_file()
            break
    pop_window.Close()
    return return_value


def get_user_input():
    srum_path = ""
    if os.path.exists("SRUDB.DAT"):
        srum_path = os.path.join(os.getcwd(), "SRUDB.DAT")
    temp_path = pathlib.Path.cwd() / "SRUM_TEMPLATE2.XLSX"
    if temp_path.exists():
        temp_path = str(temp_path)
    else:
        temp_path = ""
    reg_path = ""
    if os.path.exists("SOFTWARE"):
        reg_path = os.path.join(os.getcwd(), "SOFTWARE")

    sg.ChangeLookAndFeel('DarkRed2')
    layout = [
        [sg.Text('REQUIRED: Path to SRUDB.DAT')],
        [sg.Input(srum_path, key="_SRUMPATH_", enable_events=True), sg.FileBrowse(target="_SRUMPATH_")],
        [sg.Text('REQUIRED: Output folder for SRUM_DUMP_OUTPUT.xlsx')],
        [sg.Input(os.getcwd(), key='_OUTDIR_'), sg.FolderBrowse(target='_OUTDIR_')],
        [sg.Text('REQUIRED: Path to SRUM_DUMP Template')],
        [sg.Input(temp_path, key="_TEMPATH_"), sg.FileBrowse(target="_TEMPATH_")],
        [sg.Text('RECOMMENDED: Path to registry SOFTWARE hive')],
        [sg.Input(key="_REGPATH_"), sg.FileBrowse(target="_REGPATH_")],
        [sg.Text("Click here for support via Twitter @MarkBaggett", enable_events=True, key="_SUPPORT_", text_color="Blue")],
        [sg.OK(), sg.Cancel()]
    ]

    window = sg.Window('SRUM_DUMP 2.6', layout)

    while True:
        event, values = window.Read()
        if event is None:
            break
        if event == "_SUPPORT_":
            webbrowser.open("https://twitter.com/MarkBaggett")
        if event == 'Cancel':
            sys.exit(0)
        if event == "_SRUMPATH_":
            if str(pathlib.Path(values.get("_SRUMPATH_"))).lower() == "c:\\windows\\system32\\sru\\srudb.dat":
                result = show_live_system_warning()
                if result:
                    window.Element("_SRUMPATH_").Update(result[0])
                    window.Element("_REGPATH_").Update(result[1])
                continue
        if event == 'OK':
            tmp_path = pathlib.Path(values.get("_SRUMPATH_"))
            if not tmp_path.exists() or not tmp_path.is_file():
                sg.PopupOK("SRUM DATABASE NOT FOUND.")
                continue
            if not os.path.exists(pathlib.Path(values.get("_OUTDIR_"))):
                sg.PopupOK("OUTPUT DIR NOT FOUND.")
                continue
            tmp_path = pathlib.Path(values.get("_TEMPATH_"))
            if not tmp_path.exists() or not tmp_path.is_file():
                sg.PopupOK("SRUM TEMPLATE NOT FOUND.")
                continue
            tmp_path = pathlib.Path(values.get("_REGPATH_"))
            if values.get("_REGPATH_") and not tmp_path.exists() and not tmp_path.is_file():
                sg.PopupOK("REGISTRY File not found. (Leave field empty for None.)")
                continue
            break

    window.Close()
    options = argparse.Namespace()
    options.SRUM_INFILE = str(pathlib.Path(values.get("_SRUMPATH_")))
    options.XLSX_OUTFILE = str(pathlib.Path(values.get("_OUTDIR_")) / "SRUM_DUMP_OUTPUT.xlsx")
    options.XLSX_TEMPLATE = str(pathlib.Path(values.get("_TEMPATH_")))
    options.reghive = str(pathlib.Path(values.get("_REGPATH_")))
    if options.reghive == ".":
        options.reghive = ""
    return options