import os
import win32com.client
import subprocess
import pathlib
import hashlib
import re
import logging # Added for logging

from ui_tk import ProgressWindow

# --- Logger Setup ---
logger = logging.getLogger(f"srum_dump.copy_locked")
# --- End Logger Setup ---


def create_shadow_copy(volume_path):
    """Creates a Volume Shadow Copy for the given volume path."""
    logger.debug(f"Called create_shadow_copy with volume_path: {volume_path}")
    shadow_path = None
    try:
        logger.info(f"Attempting to create VSS for volume: {volume_path}")
        wmi_service = win32com.client.GetObject("winmgmts:\\\\.\\root\\cimv2")
        shadow_copy_class = wmi_service.Get("Win32_ShadowCopy")
        in_params = shadow_copy_class.Methods_("Create").InParameters.SpawnInstance_()
        in_params.Volume = volume_path
        in_params.Context = "ClientAccessible" # Ensures it's accessible
        logger.debug("Executing WMI Win32_ShadowCopy.Create method...")
        out_params = wmi_service.ExecMethod("Win32_ShadowCopy", "Create", in_params)

        if out_params.ReturnValue == 0:
            shadow_id = out_params.ShadowID
            logger.info(f"Successfully created Shadow Copy with ID: {shadow_id}")
            # Query for the created shadow copy to get its device object path
            shadow_copy_query = f"SELECT * FROM Win32_ShadowCopy WHERE ID='{shadow_id}'"
            logger.debug(f"Querying for shadow copy details: {shadow_copy_query}")
            shadow_copy = wmi_service.ExecQuery(shadow_copy_query)[0]
            shadow_path_raw = shadow_copy.DeviceObject
            # Convert the path format for direct access
            shadow_path = shadow_path_raw.replace("\\\\?\\", "\\\\.\\", 1)
            logger.debug(f"Shadow Copy Device Path: {shadow_path}")
        else:
            err_msg = f"Failed to create VSS. WMI ReturnValue: {out_params.ReturnValue}"
            logger.error(err_msg)
            raise Exception(err_msg) # Raise exception to be caught by caller if needed

    except Exception as e:
        logger.exception(f"Error creating shadow copy for {volume_path}: {e}")
        raise Exception(f"Unable to create VSS for {volume_path}. Error: {e}") # Re-raise with more context

    logger.debug(f"Returning shadow_path: {shadow_path}")
    return shadow_path


def extract_live_file(source, destination):
    """Extracts a live file using esentutl /vss."""
    logger.debug(f"Called extract_live_file with source: {source}, destination: {destination}")
    output = ""
    try:
        esentutl_path = pathlib.Path(os.environ.get("COMSPEC", "C:\\Windows\\System32\\cmd.exe")).parent.joinpath("esentutl.exe")
        logger.debug(f"Using esentutl path: {esentutl_path}")
        if not esentutl_path.is_file():
            err_msg = f"esentutl.exe not found at {esentutl_path}"
            logger.error(err_msg)
            raise FileNotFoundError(err_msg)

        source_path = pathlib.Path(source)
        if not source_path.is_file():
            err_msg = f"Source file not found: {source}"
            logger.error(err_msg)
            raise FileNotFoundError(err_msg)

        cmdline = f'"{esentutl_path}" /y "{source}" /vss /d "{destination}"'
        logger.info(f"Executing esentutl command: {cmdline}")
        # Using shell=True because the command string includes quotes
        result = subprocess.run(cmdline, shell=True, capture_output=True, text=True, check=False)
        output = result.stdout + result.stderr
        logger.debug(f"esentutl stdout: {result.stdout}")
        logger.debug(f"esentutl stderr: {result.stderr}")

        if result.returncode != 0:
            err_msg = f"Failed to extract file '{source}'. esentutl exited with code {result.returncode}. Output: {output}"
            logger.error(err_msg)
            raise Exception(err_msg)
        else:
            logger.info(f"Successfully extracted '{source}' to '{destination}' using esentutl.")

    except FileNotFoundError as fnf_ex:
        logger.exception(f"File not found during extraction: {fnf_ex}")
        raise # Re-raise specific error
    except Exception as e:
        logger.exception(f"Error during extract_live_file: {e}")
        raise Exception(f"Failed to extract file '{source}'. Error: {e}") # Re-raise generic error

    logger.debug(f"Returning esentutl output (truncated): {output[:200]}...")
    return output


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
    logger.debug(f"Called confirm_srum_nodes with srum_path: {srum_path}")
    is_intact = False
    full_output = ""
    try:
        # Construct the command
        esentutl_path = pathlib.Path(os.environ.get("COMSPEC", "C:\\Windows\\System32\\cmd.exe")).parent.joinpath("esentutl.exe")
        logger.debug(f"Using esentutl path: {esentutl_path}")
        if not esentutl_path.is_file():
            err_msg = f"esentutl.exe not found at {esentutl_path}"
            logger.error(err_msg)
            raise FileNotFoundError(err_msg)

        command = f'"{esentutl_path}" /g "{srum_path}"'
        logger.info(f"Executing integrity check command: {command}")

        # Run the command and capture output
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            check=False # Don't raise exception on non-zero exit code
        )
        logger.debug(f"esentutl /g stdout: {result.stdout}")
        logger.debug(f"esentutl /g stderr: {result.stderr}")
        logger.debug(f"esentutl /g return code: {result.returncode}")

        # Combine stdout and stderr into a single output string
        full_output = result.stdout + result.stderr

        # Check if the database is intact based on exit code
        is_intact = result.returncode == 0
        if is_intact:
            logger.info(f"SRUM database integrity check passed for: {srum_path}")
        else:
            logger.warning(f"SRUM database integrity check failed for: {srum_path}. Exit code: {result.returncode}")
            # Try to extract and resolve the JET error code
            error_match = re.search(r"error\s+(-?\d+)", full_output, re.IGNORECASE) # Simplified regex
            if error_match:
                error_code = int(error_match.group(1))
                error_desc = JET_ERROR_MAP.get(error_code, f"Unknown JET error code: {error_code}")
                logger.warning(f"Detected JET error code: {error_code} ({error_desc})")
                full_output += f"\n\nTranslated Error: {error_desc}"
            else:
                logger.warning("Could not extract specific JET error code from output.")
                full_output += "\n\nTranslated Error: Could not determine specific JET error code."

    except FileNotFoundError as fnf_ex:
        error_msg = f"File error during integrity check: {str(fnf_ex)}"
        logger.exception(error_msg)
        full_output = error_msg
        is_intact = False
    except Exception as e:
        error_msg = f"Error running esentutl /g: {str(e)}"
        logger.exception(error_msg)
        full_output = error_msg
        is_intact = False

    logger.debug(f"Returning from confirm_srum_nodes: is_intact={is_intact}, output (truncated)='{full_output[:200]}...'")
    return is_intact, full_output

def confirm_srum_header(srum_path):
    """
    Runs esentutl /mh on the specified SRUDB file to confirm the header state is clean.

    Args:
        srum_path (str): Path to the SRUDB file (e.g., 'C:\\path\\to\\SRUDB.dat')

    Returns:
        tuple: (bool, str) - (True if header is clean, False otherwise; command output as string)
    """
    logger.debug(f"Called confirm_srum_header with srum_path: {srum_path}")
    is_clean = False
    full_output = ""
    try:
        # Locate esentutl.exe
        esentutl_path = pathlib.Path(os.environ.get("COMSPEC", "C:\\Windows\\System32\\cmd.exe")).parent.joinpath("esentutl.exe")
        logger.debug(f"Using esentutl path: {esentutl_path}")
        if not esentutl_path.is_file():
            err_msg = f"esentutl.exe not found at {esentutl_path}"
            logger.error(err_msg)
            raise FileNotFoundError(err_msg)

        # Construct the command
        cmd = f'"{esentutl_path}" /mh "{srum_path}"'
        logger.info(f"Executing header check command: {cmd}")

        # Run the command and capture output
        res = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,  # Return output as strings, not bytes
            check=False # Don't raise exception on non-zero exit code
        )
        logger.debug(f"esentutl /mh stdout: {res.stdout}")
        logger.debug(f"esentutl /mh stderr: {res.stderr}")
        logger.debug(f"esentutl /mh return code: {res.returncode}")

        # Combine stdout and stderr into a single output string
        full_output = res.stdout + res.stderr

        # Check if the command executed successfully first
        if res.returncode != 0:
            err_msg = f"Header check command failed with exit code {res.returncode}"
            logger.error(err_msg)
            full_output += f"\n\nError: {err_msg}"
            # No need to check state if command failed
        else:
            # Extract the State field using regex
            state_match = re.search(r"State:\s*(.+)", full_output, re.IGNORECASE) # Added ignorecase
            if state_match:
                state = state_match.group(1).strip()
                logger.info(f"Database state reported as: '{state}'")
                is_clean = state.lower() == "clean shutdown" # Case-insensitive compare
                if not is_clean:
                    logger.warning(f"Database state is '{state}', not 'Clean Shutdown'.")
                    full_output += f"\n\nHeader Check Result: Database state is '{state}' (Expected 'Clean Shutdown')"
                else:
                    logger.info("Database state is 'Clean Shutdown'.")
            else:
                logger.error("Could not determine database state from esentutl /mh output.")
                full_output += "\n\nError: Could not determine database state from output"
                is_clean = False # Treat as not clean if state cannot be determined

    except FileNotFoundError as fnf_ex:
        error_msg = f"File error during header check: {str(fnf_ex)}"
        logger.exception(error_msg)
        full_output = error_msg
        is_clean = False
    except Exception as e:
        error_msg = f"Error running esentutl /mh: {str(e)}"
        logger.exception(error_msg)
        full_output = error_msg
        is_clean = False

    logger.debug(f"Returning from confirm_srum_header: is_clean={is_clean}, output (truncated)='{full_output[:200]}...'")
    return is_clean, full_output



def file_copy_cmd(src, dest):
    """Copies file(s) using the native 'copy' command."""
    logger.debug(f"Called file_copy_cmd with src: {src}, dest: {dest}")
    # Use /Y to suppress overwrite prompts, /V to verify
    cmd_copy = f'copy /Y /V "{src}" "{dest}"'
    logger.info(f"Executing copy command: {cmd_copy}")
    res = subprocess.run(cmd_copy, shell=True, capture_output=True, text=True, check=False)
    logger.debug(f"Copy command stdout: {res.stdout}")
    logger.debug(f"Copy command stderr: {res.stderr}")
    logger.debug(f"Copy command return code: {res.returncode}")
    if res.returncode != 0:
        logger.error(f"Copy command failed with exit code {res.returncode}. Output: {res.stdout + res.stderr}")
    else:
        logger.info(f"Copy command completed for src: {src}")
    return res

def verify_and_recopy_file(src, dest, ui_window):
    """Copies src to dest, verifies MD5 hash, retries copy if mismatch, returns success status."""
    logger.debug(f"Called verify_and_recopy_file with src: {src}, dest: {dest}")
    success = False # Assume failure initially
    retry = 3
    max_retries = retry # Store max retries for logging
    while retry > 0:
        logger.info(f"Verifying hash for src: {src}, dest: {dest}. Attempt {max_retries - retry + 1}/{max_retries}")
        hashes_match = verify_file_hashes(src, dest)
        if hashes_match:
            logger.info(f"Hashes match for src: {src}, dest: {dest}")
            success = True
            break # Exit loop on success
        else:
            logger.warning(f"Hash mismatch for src: {src}, dest: {dest}. Retrying copy.")
            ui_window.log_message(f"WARNING: Hash mismatch for {pathlib.Path(src).name}. Retrying copy ({max_retries - retry + 1}/{max_retries})...")
            retry -= 1
            ui_window.set_current_table(f"Recopying {pathlib.Path(src).name}")
            res = file_copy_cmd(src, dest)
            # Log copy result to UI and logger
            copy_output = res.stdout + res.stderr
            ui_window.log_message(f"Recopy attempt output: {copy_output}")
            logger.debug(f"Recopy attempt output for {src}: {copy_output}")
            if res.returncode != 0:
                 logger.error(f"Recopy attempt failed for {src}. Return code: {res.returncode}")
                 # Optionally break here if copy fails, or let hash check fail again
            # Loop continues to re-verify hash

    if not success:
        err_msg = f"Failed to copy and verify file after {max_retries} attempts: src={src}, dest={dest}"
        logger.error(err_msg)
        ui_window.log_message(f"ERROR: Unable to copy and verify {pathlib.Path(src).name} after {max_retries} attempts.")

    logger.debug(f"Returning from verify_and_recopy_file with success: {success}")
    return success

def verify_file_hashes(original, copy):
    """Calculates and compares MD5 hashes of two files."""
    logger.debug(f"Called verify_file_hashes with original: {original}, copy: {copy}")
    original_hash = None
    copy_hash = None
    match = False
    try:
        original_path = pathlib.Path(original)
        copy_path = pathlib.Path(copy)

        if not original_path.is_file():
            logger.error(f"Original file not found for hashing: {original}")
            return False
        if not copy_path.is_file():
            logger.error(f"Copy file not found for hashing: {copy}")
            return False

        logger.debug(f"Calculating MD5 for original: {original}")
        original_hash = hashlib.md5(original_path.read_bytes()).hexdigest()
        logger.debug(f"Original MD5: {original_hash}")

        logger.debug(f"Calculating MD5 for copy: {copy}")
        copy_hash = hashlib.md5(copy_path.read_bytes()).hexdigest()
        logger.debug(f"Copy MD5: {copy_hash}")

        match = original_hash == copy_hash
        logger.info(f"Hash comparison result for {original_path.name}: {'Match' if match else 'Mismatch'}")

    except Exception as e:
        logger.exception(f"Error calculating or comparing file hashes: {e}")
        match = False # Treat errors as mismatch

    logger.debug(f"Returning hash match result: {match}")
    return match

def copy_locked_files(destination_folder: pathlib.Path):
    """
    Copies locked SRUM and SOFTWARE files using VSS and verifies integrity.

    :param destination_folder: Path to save the copied files
    """
    logger.debug(f"Called copy_locked_files with destination_folder: {destination_folder}")
    ui_window = ProgressWindow("Extracting Locked files")
    ui_window.hide_record_stats()
    ui_window.start(6) # Adjust steps if needed (VSS, Copy SRU, Verify SRU, Check SRU, Copy Reg, Verify Reg)
    success = True # Assume success unless something fails
    shadow_path = None # Initialize shadow_path

    try:
        # --- Step 1: Create Volume Shadow Copy ---
        ui_window.set_current_table("Creating Volume Shadow Copy")
        volume = pathlib.Path(os.environ["SystemRoot"]).drive
        
        ui_window.log_message(f"Creating a volume shadow copy for {volume}... Please be patient.")
        logger.info(f"Attempting VSS creation for volume {volume}")
        try:
            shadow_path = create_shadow_copy(f"{volume}\\")
            ui_window.log_message(f"[+] Shadow Copy Device: {shadow_path}")
            logger.info(f"VSS created successfully: {shadow_path}")
        except Exception as vss_e:
            err_msg = f"[-] Failed to create shadow copy: {vss_e}"
            ui_window.log_message(err_msg)
            logger.exception(err_msg) # Log the full exception
            success = False
            # No point continuing if VSS fails
            raise Exception("VSS Creation Failed") from vss_e

        # --- Step 2: Copy SRUM files ---
        ui_window.set_current_table("Copying SRU Folder")
        ui_window.log_message("Copying SRUM files from shadow copy...")
        sru_source_dir = shadow_path + r"\Windows\system32\sru\*"
        logger.info(f"Copying SRUM files from {sru_source_dir} to {destination_folder}")
        res_sru_copy = file_copy_cmd(sru_source_dir, str(destination_folder))
        copy_output_sru = res_sru_copy.stdout + res_sru_copy.stderr
        ui_window.log_message(f"SRUM copy output: {copy_output_sru}")
        logger.info(f"SRUM copy output: {copy_output_sru}")
        if res_sru_copy.returncode != 0:
            logger.error("SRUM file copy command failed.")
            success = False
            # Decide if we should stop or try verification anyway
            # For now, let's try verification even if copy reported errors

        # --- Step 3: Verify SRUM Copy ---
        ui_window.set_current_table("Confirming SRUM Integrity")
        ui_window.log_message("Verifying SRUM database copy integrity (MD5 Hash)...")
        new_srum_path = destination_folder.joinpath("srudb.dat")
        orig_srum_path_in_vss = pathlib.Path(shadow_path + r"\Windows\system32\sru\srudb.dat")
        logger.info(f"Verifying hash between {orig_srum_path_in_vss} and {new_srum_path}")
        good_srum_copy = verify_and_recopy_file(str(orig_srum_path_in_vss), str(new_srum_path), ui_window)
        success = success and good_srum_copy # Update overall success
        if not good_srum_copy:
            ui_window.log_message("ERROR: Unable to get a verified copy of SRUDB.dat.")
            logger.error("SRUDB.dat verification failed after retries.")
            # Consider stopping here if SRUM is critical
            # return False # Optional: exit early
        else:
            ui_window.log_message("SRUM database copy verified successfully.")
            logger.info("SRUDB.dat copy verified.")

        # --- Step 4: Check SRUM Health (Header & Nodes) ---
        if new_srum_path.exists(): # Only check if the file exists
            ui_window.set_current_table("Checking SRUM Health")
            ui_window.log_message("Checking SRUM database header state...")
            logger.info(f"Checking header state for {new_srum_path}")
            good_headers, header_output = confirm_srum_header(str(new_srum_path))
            ui_window.log_message(f"Header Check Output:\n{header_output}")
            logger.info(f"Header Check Output:\n{header_output}")
            if not good_headers:
                logger.warning("SRUM header check failed.")
                ui_window.log_message("WARNING: SRUM header indicates potential issues (not 'Clean Shutdown').")
            else:
                logger.info("SRUM header check passed ('Clean Shutdown').")
                ui_window.log_message("SRUM header confirmed.")

            ui_window.log_message("Checking SRUM database integrity (esentutl /g)...")
            logger.info(f"Checking integrity for {new_srum_path}")
            good_nodes, nodes_output = confirm_srum_nodes(str(new_srum_path))
            ui_window.log_message(f"Integrity Check Output:\n{nodes_output}")
            logger.info(f"Integrity Check Output:\n{nodes_output}")
            if not good_nodes:
                logger.warning("SRUM integrity check failed (esentutl /g).")
                ui_window.log_message("WARNING: SRUM integrity check failed.")
            else:
                logger.info("SRUM integrity check passed (esentutl /g).")
                ui_window.log_message("SRUM database integrity confirmed.")

            # --- Step 4b: Attempt Repair if Needed ---
            if good_srum_copy and (not good_headers or not good_nodes):
                ui_window.log_message("SRUM issues detected. Attempting repair...")
                logger.warning("Attempting SRUM repair due to header/integrity issues.")
                # Repair srum based on log files (Recovery)
                ui_window.set_current_table("Recovering SRUM Database")
                cmd_recover = 'esentutl.exe /r sru /i' # Assumes log files are named sru*.log
                ui_window.log_message(f"Running recovery command: {cmd_recover}")
                logger.info(f"Running recovery command in {destination_folder}: {cmd_recover}")
                res_recover = subprocess.run(cmd_recover, shell=True, cwd=destination_folder, capture_output=True, text=True, check=False)
                recover_output = res_recover.stdout + res_recover.stderr
                ui_window.log_message(f"Recovery output: {recover_output}")
                logger.info(f"Recovery output: {recover_output}")
                if res_recover.returncode != 0:
                    logger.error(f"SRUM recovery failed. Return code: {res_recover.returncode}")
                else:
                    logger.info("SRUM recovery command completed.")

                # Repair srum database file (Repair)
                ui_window.set_current_table("Repairing SRUM Database")
                cmd_repair = 'esentutl.exe /p SRUDB.dat'
                ui_window.log_message(f"Running repair command: {cmd_repair} (This may take a while and might result in data loss)")
                logger.info(f"Running repair command in {destination_folder}: {cmd_repair}")
                # Note: /p often requires user interaction if run directly. Might need input='Y\n'.
                # For non-interactive, consider if this step is appropriate or if recovery (/r) is sufficient.
                # Let's run it without input first.
                res_repair = subprocess.run(cmd_repair, shell=True, cwd=destination_folder, capture_output=True, text=True, check=False)
                repair_output = res_repair.stdout + res_repair.stderr
                ui_window.log_message(f"Repair output: {repair_output}")
                logger.info(f"Repair output: {repair_output}")
                if res_repair.returncode != 0:
                    logger.error(f"SRUM repair failed. Return code: {res_repair.returncode}")
                    success = False # Mark as failed if repair fails
                    ui_window.log_message("ERROR: SRUM repair command failed.")
                else:
                    logger.info("SRUM repair command completed.")

                # Re-check headers and nodes after repair attempt
                ui_window.set_current_table("Re-checking SRUM Health")
                ui_window.log_message("Re-checking SRUM headers after repair...")
                logger.info("Re-checking SRUM headers post-repair.")
                good_headers_post, header_output_post = confirm_srum_header(str(new_srum_path))
                ui_window.log_message(f"Post-Repair Header Check Output:\n{header_output_post}")
                logger.info(f"Post-Repair Header Check Output:\n{header_output_post}")
                if not good_headers_post:
                    logger.error("SRUM header check failed even after repair.")
                    ui_window.log_message("ERROR: Unable to repair SRUM header.")
                    success = False # Mark as failed

                ui_window.log_message("Re-checking SRUM integrity after repair...")
                logger.info("Re-checking SRUM integrity post-repair.")
                good_nodes_post, nodes_output_post = confirm_srum_nodes(str(new_srum_path))
                ui_window.log_message(f"Post-Repair Integrity Check Output:\n{nodes_output_post}")
                logger.info(f"Post-Repair Integrity Check Output:\n{nodes_output_post}")
                if not good_nodes_post:
                    logger.error("SRUM integrity check failed even after repair.")
                    ui_window.log_message("ERROR: Unable to repair SRUM integrity.")
                    success = False # Mark as failed
        else:
             logger.error(f"Skipping SRUM health checks because file does not exist: {new_srum_path}")
             ui_window.log_message(f"ERROR: Copied SRUDB.dat not found at {new_srum_path}. Cannot check health.")
             success = False


        # --- Step 5: Copy SOFTWARE Hive ---
        ui_window.set_current_table("Copying SOFTWARE Hive")
        ui_window.log_message("Copying registry SOFTWARE hive from shadow copy...")
        reg_source_path = shadow_path + r"\Windows\system32\config\SOFTWARE"
        reg_dest_path = destination_folder.joinpath("SOFTWARE")
        logger.info(f"Copying SOFTWARE hive from {reg_source_path} to {reg_dest_path}")
        res_reg_copy = file_copy_cmd(reg_source_path, str(reg_dest_path))
        copy_output_reg = res_reg_copy.stdout + res_reg_copy.stderr
        ui_window.log_message(f"SOFTWARE copy output: {copy_output_reg}")
        logger.info(f"SOFTWARE copy output: {copy_output_reg}")
        if res_reg_copy.returncode != 0:
             logger.error("SOFTWARE hive copy command failed.")
             success = False # Mark failure but continue to verification attempt

        # --- Step 6: Verify SOFTWARE Copy ---
        ui_window.log_message("Verifying registry SOFTWARE hive copy integrity (MD5 Hash)...")
        logger.info(f"Verifying hash between {reg_source_path} and {reg_dest_path}")
        good_reg_copy = verify_and_recopy_file(reg_source_path, str(reg_dest_path), ui_window)
        success = success and good_reg_copy # Update overall success
        if not good_reg_copy:
            ui_window.log_message("ERROR: Unable to get a verified copy of SOFTWARE hive.")
            logger.error("SOFTWARE hive verification failed after retries.")
        else:
            ui_window.log_message("SOFTWARE hive copy verified successfully.")
            logger.info("SOFTWARE hive copy verified.")

    except Exception as main_ex:
        # Catch any unexpected errors during the process
        logger.exception(f"An unexpected error occurred during copy_locked_files: {main_ex}")
        ui_window.log_message(f"CRITICAL ERROR during extraction: {main_ex}")
        success = False

    finally:
        # --- Final UI Update ---
        ui_window.set_current_table("Finished")
        if success:
            final_msg = "Locked file extraction process finished. Check logs above for details."
            logger.info(final_msg)
            ui_window.log_message(final_msg)
        else:
            final_msg = "Locked file extraction process finished with ERRORS. Please review logs carefully."
            logger.error(final_msg)
            ui_window.log_message(f"ERROR: {final_msg}")

        if not success:
            ui_window.log_message("Errors occured. Review the messages above and rerun this program to try again.\n")
            ui_window.log_message("Close this Window to proceed.")
            ui_window.finished()
            try:
                # Ensure mainloop runs even if errors occurred to show messages
                ui_window.root.mainloop()
            except Exception as ui_ex:
                logger.error(f"Error during final UI mainloop: {ui_ex}")
        else:
            ui_window.close()

    logger.info(f"copy_locked_files finished with overall success status: {success}")
    return success


# Example usage (commented out)
# if __name__ == "__main__":
#     logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
#     dest = pathlib.Path("./output_test")
#     dest.mkdir(exist_ok=True)
#     copy_locked_files(dest)
