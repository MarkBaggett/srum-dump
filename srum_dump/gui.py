import PySimpleGUI as sg
import webbrowser
import pathlib
import os
import ctypes
import tempfile
import subprocess
import urllib

class SRUMDumpGUI:
    def __init__(self):
        self.layout = [
            [sg.Text('REQUIRED: Path to SRUDB.DAT')],
            [sg.Input(key="_SRUMPATH_", enable_events=True), sg.FileBrowse(target="_SRUMPATH_")],
            [sg.Text('REQUIRED: Output folder for SRUM_DUMP_OUTPUT.xlsx')],
            [sg.Input(os.getcwd(), key='_OUTDIR_'), sg.FolderBrowse(target='_OUTDIR_')],
            [sg.Text('REQUIRED: Path to SRUM_DUMP Template')],
            [sg.Input(key="_TEMPATH_"), sg.FileBrowse(target="_TEMPATH_")],
            [sg.Text('RECOMMENDED: Path to registry SOFTWARE hive')],
            [sg.Input(key="_REGPATH_"), sg.FileBrowse(target="_REGPATH_")],
            [sg.Text("Click here for support via Twitter @MarkBaggett", enable_events=True, key="_SUPPORT_", text_color="Blue")],
            [sg.OK(), sg.Cancel()]]

        self.window = sg.Window('SRUM_DUMP 2.6', self.layout)

    def run(self):
        while True:
            event, values = self.window.Read()
            if event is None:
                break
            if event == "_SUPPORT_":
                webbrowser.open("https://twitter.com/MarkBaggett")
            if event == 'Cancel':
                self.window.Close()
                return None
            if event == "_SRUMPATH_":
                if str(pathlib.Path(values.get("_SRUMPATH_"))).lower() == "c:\\windows\\system32\\sru\\srudb.dat":
                    result = self.show_live_system_warning()
                    if result:
                        self.window.Element("_SRUMPATH_").Update(result[0])
                        self.window.Element("_REGPATH_").Update(result[1])
                    continue
            if event == 'OK':
                self.window.Close()
                return {
                    "SRUM_INFILE": str(pathlib.Path(values.get("_SRUMPATH_"))),
                    "XLSX_OUTFILE": str(pathlib.Path(values.get("_OUTDIR_")) / "SRUM_DUMP_OUTPUT.xlsx"),
                    "XLSX_TEMPLATE": str(pathlib.Path(values.get("_TEMPATH_"))),
                    "REG_HIVE": str(pathlib.Path(values.get("_REGPATH_")))
                }

    def show_live_system_warning(self):
        layout = [
            [sg.Text("It appears your trying to open SRUDB.DAT from a live system.")],
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
                return_value = self.extract_live_file()
                break
        pop_window.Close()
        return return_value


    def extract_live_file():
        try:
            tmp_dir = tempfile.mkdtemp()
            #fget_file = tempfile.NamedTemporaryFile(mode="w+b", suffix=".exe",delete=False)
            fget_file = pathlib.Path(tmp_dir) / "fget.exe"
            #registry_file = tempfile.NamedTemporaryFile(mode="w+b", suffix = ".reg", delete=False)
            registry_file = pathlib.Path(tmp_dir) / "SOFTWARE"
            #extracted_srum = tempfile.NamedTemporaryFile(mode="w+b", suffix = ".dat", delete=False
            extracted_srum = pathlib.Path(tmp_dir) / "srudb.dat"
            esentutl_path = pathlib.Path(os.environ.get("COMSPEC")).parent / "esentutl.exe"
            if esentutl_path.exists():
                print("Extracting srum with esentutl.exe")
                cmdline = r"{} /y c:\\windows\\system32\\sru\\srudb.dat /vss /d {}".format(str(esentutl_path), str(extracted_srum))
                print(cmdline)
                phandle = subprocess.Popen(cmdline, shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out1,_ = phandle.communicate()
                print("Extracting Registry with esentutl.exe")
                cmdline = r"{} /y c:\\windows\\system32\\config\\SOFTWARE /vss /d {}".format(str(esentutl_path), str(registry_file))
                print(cmdline)
                phandle = subprocess.Popen(cmdline, shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out2,_ = phandle.communicate()
            else:
                print("Downloading fget.exe to {}".format(str(fget_file)))
                fget_binary = urllib.request.urlopen('https://github.com/MarkBaggett/srum-dump/raw/master/FGET.exe').read()
                fget_file.write_bytes(fget_binary)
                print("Extracting srum with fget.exe")
                cmdline = r"{} -extract c:\\windows\\system32\\sru\srudb.dat {}".format(str(fget_file), str(extracted_srum))
                print(cmdline)
                phandle = subprocess.Popen(cmdline, shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out1,_ = phandle.communicate()
                cmdline = r"{} -extract c:\\windows\\system32\\config\SOFTWARE {}".format(str(fget_file), str(registry_file))
                print(cmdline)
                phandle = subprocess.Popen(cmdline, shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out2,_ = phandle.communicate()
                fget_file.unlink()
        except Exception as e:
            print("Unable to automatically extract srum. {}\n{}\n{}".format(str(e), out1.decode(), out2.decode()))
            return None
        if (b"returned error" in out1+out2) or (b"Init failed" in out1+out2):
            print("ERROR\n SRUM Extraction: {}\n Registry Extraction {}".format(out1.decode(),out2.decode()))
        elif b"success" in out1.lower() and b"success" in out2.lower():
            return str(extracted_srum), str(registry_file)
        else:
            print("Unable to determine success or failure.", out1.decode(),"\n",out2.decode())
        return None
    

