import os
import win32com.client
import subprocess
import pathlib
import hashlib
import re

from ui_tk import ProgressWindow


def create_shadow_copy(volume_path):
    wmi_service = win32com.client.GetObject("winmgmts:\\\\.\\root\\cimv2")
    shadow_copy_class = wmi_service.Get("Win32_ShadowCopy")
    in_params = shadow_copy_class.Methods_("Create").InParameters.SpawnInstance_()
    in_params.Volume = volume_path
    in_params.Context = "ClientAccessible"
    out_params = wmi_service.ExecMethod("Win32_ShadowCopy", "Create", in_params)
    if out_params.ReturnValue == 0:
        shadow_id = out_params.ShadowID
        shadow_copy = wmi_service.ExecQuery(f"SELECT * FROM Win32_ShadowCopy WHERE ID='{shadow_id}'")[0]
        shadow_path = shadow_copy.DeviceObject.replace("\\\\?\\", "\\\\.\\", 1)
        return shadow_path
    else:
        raise Exception("Unable to create VSS.")


def extract_live_file(source, destination):
    esentutl_path = pathlib.Path(os.environ.get("COMSPEC")).parent.joinpath("esentutl.exe")
    if not esentutl_path.is_file():
        raise FileNotFoundError("esentutl.exe not found")
    if not pathlib.Path(source).is_file():
        raise FileNotFoundError("Source file not found")

    cmdline = f"{str(esentutl_path)} /y {source} /vss /d {destination}"
    result = subprocess.run(cmdline.split(), shell=True, capture_output=True)
    if result.returncode != 0:
        raise Exception(f"Failed to extract file {result.stderr.decode()}")
    return result.stdout.decode()


import subprocess
import re

# Mapping of common JET error codes to user-friendly descriptions
JET_ERROR_MAP = {
    -1018: "JET_errReadVerifyFailure: Read verification error (checksum mismatch on a page)",
    -1019: "JET_errPageNotInitialized: Page not initialized (likely corruption)",
    -1022: "JET_errDiskIO: Disk I/O error (problem reading/writing to file)",
    -1206: "JET_errDatabaseCorrupted: Database is corrupted",
    -550: "JET_errInvalidParameter: Invalid parameter passed to the operation",
    -1003: "JET_errOutOfMemory: Out of memory during operation",
    -1032: "JET_errFileAccessDenied: Access denied to the database file",
    -1811: "JET_errFileNotFound: Database file not found",
    0: "No error: Operation completed successfully"
}


def confirm_srum_nodes(srum_path):
    """
    Runs esentutl /g on the specified SRUDB file and checks if it's intact based on exit code.
    Resolves JET error codes to user-friendly strings if an error occurs.

    Args:
        srum_path (str): Path to the SRUDB file (e.g., 'C:\\path\\to\\SRUDB.dat')

    Returns:
        tuple: (bool, str) - (True if intact, False otherwise; command output with error details)
    """
    try:
        # Construct the command
        esentutl_path = pathlib.Path(os.environ.get("COMSPEC", "C:\\Windows\\System32\\cmd.exe")).parent.joinpath(
            "esentutl.exe")
        if not esentutl_path.is_file():
            raise FileNotFoundError(f"esentutl.exe not found at {esentutl_path}")

        command = f'{esentutl_path} /g "{srum_path}"'

        # Run the command and capture output
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            check=False
        )

        # Combine stdout and stderr into a single output string
        full_output = result.stdout + result.stderr

        # Check if the database is intact based on exit code
        is_intact = result.returncode == 0

        # If there's an error, try to extract and resolve the JET error code
        if not is_intact:
            # Look for patterns like "Error: -1018" or "error -1018" in the output
            error_match = re.search(r"Error:\s*(-?\d+)|error\s*(-?\d+)", full_output, re.IGNORECASE)
            if error_match:
                # Extract the error code from the first non-None match group
                error_code = int(error_match.group(1) or error_match.group(2))
                # Get the user-friendly description, or use a default if unknown
                error_desc = JET_ERROR_MAP.get(error_code, f"Unknown JET error code: {error_code}")
                full_output += f"\n\nTranslated Error: {error_desc}"
            else:
                full_output += f"\n\nTranslated Error: JET error code"

        return is_intact, full_output
    except Exception as e:
        # Handle execution errors
        error_msg = f"Error running esentutl: {str(e)}"
        return False, error_msg

def confirm_srum_header(srum_path):
    """
    Runs esentutl /mh on the specified SRUDB file to confirm the header state is clean.

    Args:
        srum_path (str): Path to the SRUDB file (e.g., 'C:\\path\\to\\SRUDB.dat')

    Returns:
        tuple: (bool, str) - (True if header is clean, False otherwise; command output as string)
    """
    try:
        # Locate esentutl.exe in the system directory (typically C:\Windows\System32)
        esentutl_path = pathlib.Path(os.environ.get("COMSPEC", "C:\\Windows\\System32\\cmd.exe")).parent.joinpath(
            "esentutl.exe")
        if not esentutl_path.is_file():
            raise FileNotFoundError(f"esentutl.exe not found at {esentutl_path}")

        # Construct the command
        cmd = f'"{esentutl_path}" /mh "{srum_path}"'

        # Run the command and capture output
        res = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,  # Return output as strings, not bytes
            check=False
        )

        # Combine stdout and stderr into a single output string
        full_output = res.stdout + res.stderr

        # Check if the command executed successfully
        if res.returncode != 0:
            full_output += f"\n\nError: Command failed with exit code {res.returncode}"
            return False, full_output

        # Extract the State field using regex
        state_match = re.search(r"State:\s*(.+)", full_output)
        if state_match:
            state = state_match.group(1).strip()
            is_clean = state == "Clean Shutdown"
            if not is_clean:
                full_output += f"\n\nHeader Check Result: Database state is '{state}' (not 'Clean Shutdown')"
            return is_clean, full_output
        else:
            full_output += "\n\nError: Could not determine database state from output"
            return False, full_output

    except FileNotFoundError as e:
        error_msg = f"File error: {str(e)}"
        return False, error_msg
    except Exception as e:
        error_msg = f"Error running esentutl /mh: {str(e)}"
        return False, error_msg



def file_copy_cmd(src, dest):
    #Copies file with file copy command
    cmd_copy = f'copy /V "{src}" "{dest}" '
    res = subprocess.run(cmd_copy, shell=True, capture_output=True)
    return res

def verify_and_recopy_file(src, dest, ui_window):
    #copies src to dst
    #Confirms MD5 of files match
    #retries the copy if the do not
    #returns success if the copies and it matches
    success = True
    retry = 3
    while not verify_file_hashes(src, dest) and retry > 0:
        ui_window.log_message(f"WARNING: {src} did not match original. Retrying copy command.")
        retry -= 1
        ui_window.set_current_table("Copying SRU Folder")
        res = file_copy_cmd(src, dest)
        ui_window.log_message(res.stdout().decode() + res.stderr.decode())
    if retry == 0:
        success = False
        ui_window.log_message("WARNING: Unable to copy file and get matching hashes")
    return success

def verify_file_hashes(original, copy):
    original_hash = hashlib.md5( pathlib.Path(original).read_bytes()).digest()
    copy_hash = hashlib.md5( pathlib.Path(copy).read_bytes()).digest()
    return original_hash == copy_hash

def copy_locked_files(destination_folder: pathlib.Path):
    """
    Copies a locked file using Volume Shadow Copy Service (VSS) and copy.
    
    :param source: Full path to the locked file (e.g., C:\\Windows\\System32\\SRU\\srudb.dat)
    :param destination: Path to save the copied file
    """
    ui_window = ProgressWindow("Extracting Locked files")
    ui_window.hide_record_stats()
    ui_window.start(6)
    ui_window.set_current_table("Creating Volume Shadow Copy")
    volume = pathlib.Path(os.environ["SystemRoot"]).drive
    ui_window.log_message("Note: There are known issues with extracting a srudb.dat from live Windows 11 systems that results in corrupt srudb.dat files. You are encouraged to extract the files from a forensics image.\nBest effort being applied \n")
    ui_window.log_message(f"Creating a volume shadow copy for {volume}\n")
    success = True
    
    # Create the shadow copy
    try:
        shadow_path = create_shadow_copy(f"{volume}\\")
    except Exception as e:
        ui_window.log_message(str(e))
        success = False
    else:
        ui_window.log_message(f"[+] Shadow Copy Device: {shadow_path}\n")

    if isinstance(shadow_path, int):
        ui_window.log_message(f"[-] Failed to create shadow copy: {shadow_path}\n")
        success = False


    if success:
        # Copy the sru directory to destination
        ui_window.log_message("Copying SRUM to output folder")
        file_path = shadow_path + r"\Windows\system32\sru\*"
        ui_window.set_current_table("Copying SRU Folder")
        res = file_copy_cmd(file_path, destination_folder)
        success = success and (res.returncode == 0)
        ui_window.log_message(res.stdout.decode() + res.stderr.decode())

        #Copy SRUM and confirm hashes
        ui_window.set_current_table("Confirming copy SRUM Integrity")
        ui_window.log_message("Confirming hashes and recopying as needed.")
        new_srum = pathlib.Path(destination_folder).joinpath("srudb.dat")
        orig_srum = pathlib.Path(file_path).parent.joinpath("srudb.dat")
        good_srum = verify_and_recopy_file(new_srum, orig_srum, ui_window)

        if not good_srum:
            ui_window.log_message("Unable to cleanly extract the SRUM")
            return False
        else:
            ui_window.log_message("SRUM integrity confirmed. New hashes match source.")

        #Confirm good headers and nodes
        ui_window.set_current_table("Checking SRUM headers and nodes.")
        ui_window.log_message("Confirming SRUM headers")
        good_headers, output = confirm_srum_header(new_srum)
        if not good_headers:
            ui_window.log_message(output)
        else:
            ui_window.log_message("SRUM headers confirmed.")
        ui_window.log_message("Confirming SRUM database records")
        good_nodes, output = confirm_srum_nodes(new_srum)
        if not good_nodes:
            ui_window.log_message(output)
        else:
            ui_window.log_message("SRUM database records confirmed.")

        #If hashes match but state is not clean or bad nodes repair
        if not good_headers or not good_nodes:
            ui_window.log_message("SRUM Corruption detected. Attempting rebulding of SRUM Table")
            # Repair srum based on log files
            ui_window.set_current_table("Corrupt SRUM Detected. Recovering SRU Folder")
            #We will set the destination folder in the subprocess run so sru is in the current directory
            cmd_copy = f'esentutl.exe /r sru /i '
            ui_window.log_message(cmd_copy)
            res = subprocess.run(cmd_copy, shell=True, cwd=destination_folder, capture_output=True)
            success = success and (res.returncode == 0)
            ui_window.log_message(res.stdout.decode() + res.stderr.decode())
            # Repair srum based on log files
            ui_window.set_current_table("Repair SRUM Database")
            cmd_copy = f'esentutl.exe /p SRUDB.dat'
            ui_window.log_message(cmd_copy)
            res = subprocess.run(cmd_copy, shell=True, cwd=destination_folder, capture_output=True)
            success = success and (res.returncode == 0)
            ui_window.log_message(res.stdout.decode() + res.stderr.decode())

            #Check headers and nodes again after repair
            ui_window.set_current_table("Checking again after rebuild")
            ui_window.log_message("Confirming SRUM headers")
            good_headers, output = confirm_srum_header(new_srum)
            if not good_headers:
                ui_window.log_message(output)
                ui_window.log_message("Unable to repair srum")
                return False
            ui_window.log_message("Confirming SRUM database nodes")
            good_nodes, output = confirm_srum_nodes(new_srum)
            if not good_nodes:
                ui_window.log_message(output)
                ui_window.log_message("Unable to repair srum")
                return False

        # Copy the SOFTWARE key to destination
        file_path = shadow_path + r"\Windows\system32\config\SOFTWARE"
        dest_file = str(pathlib.Path(destination_folder).joinpath("SOFTWARE"))
        ui_window.set_current_table("Copying SOFTWARE")
        ui_window.log_message("Copying registry SOFTWARE hive")
        res = file_copy_cmd(file_path, dest_file)
        ui_window.log_message(res.stdout.decode() + res.stderr.decode())
        ui_window.log_message("Verifying registry SOFTWARE hive")
        success = success and verify_and_recopy_file(file_path, dest_file, ui_window)
        ui_window.log_message(f"Software hive integrity verification: {str(success)}")


    ui_window.set_current_table("Finished")
    ui_window.log_message("The srum extraction has finished. Check the logs above for any errors.\n")
    ui_window.log_message("Close this Window to proceed.")
    ui_window.finished()
    ui_window.root.mainloop()

    return success


#copy_locked_files(r"c:\Users\mark\Desktop\output")