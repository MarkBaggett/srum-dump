import pathlib
import struct
import os
import tempfile
import urllib.request
import subprocess
import codecs
import re
import itertools
import logging # Added for logging

from datetime import datetime, timezone, timedelta
from Registry import Registry

# --- Logger Setup ---
# Get a logger for this module
logger = logging.getLogger(f"srum_dump.helpers")
# --- End Logger Setup ---


manager = logging.Logger.manager.loggerDict
logger.debug(f"{'*'*1000}")
for n,l in manager.items(): 
    if not isinstance(l, logging.PlaceHolder):
        logger.debug(f"{n},{l.level},{l.handlers},{l.propagate}")
logger.debug(f"{'*'*1000}")


skip_tables = ['MSysObjects', 'MSysObjectsShadow', 'MSysObjids', 'MSysLocales','SruDbIdMapTable', 'SruDbCheckpointTable']

dirty_words = {
    'put a process user or wifi network name here before the colon': 'general-red-bold',
    'After the colon put a color in all caps':'highlight-red',
    'These dirty words SIGNIFICANTLY impact performance use with caution':'highlight-yellow'
}

known_sids = {
    "S-1-0-0": "Null SID",
    "S-1-1-0": "Everyone",
    "S-1-2-0": "Local",
    "S-1-2-1": "Console Logon",
    "S-1-3-0": "Creator Owner",
    "S-1-3-1": "Creator Group",
    "S-1-3-2": "Creator Owner Server",
    "S-1-3-3": "Creator Group Server",
    "S-1-5-1": "Dialup",
    "S-1-5-2": "Network",
    "S-1-5-3": "Batch",
    "S-1-5-4": "Interactive",
    "S-1-5-6": "Service",
    "S-1-5-7": "Anonymous",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Principal Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-12": "Restricted Code",
    "S-1-5-13": "Terminal Server Users",
    "S-1-5-18": "Local System",
    "S-1-5-19": "Local Service",
    "S-1-5-20": "Network Service",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-5-32-547": "Power Users",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-552": "Replicator"
}

known_tables = {
    '{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}': 'Application Resource Usage', 
    '{5C8CF1C7-7257-4F13-B223-970EF5939312}': 'App Timeline Provider', 
    '{DA73FB89-2BEA-4DDC-86B8-6E048C6DA477}': 'Energy Estimator Provider', 
    '{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}': 'Energy Usage', 
    '{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT': 'Energy Usage Long Term', 
    '{DD6636C4-8929-4683-974E-22C046A43763}': 'Network Connectivity Usage', 
    '{973F5D5C-1D90-4944-BE8E-24B94231A174}': 'Network Data Usage', 
    '{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}': 'Push Notifications', 
    '{DC3D3B50-BB90-5066-FA4E-A5F90DD8B677}': 'SDP CPU', 
    '{CDF8EBF6-7C0F-5AC2-158F-DBFBEE981152}': 'SDP Event Log', 
    '{EEE2F477-0659-5C47-EF03-6D6BEFD441B3}': 'SDP Network', 
    '{38AD6548-9313-58F8-45C7-D293BAFDC879}': 'SDP Performance Counter', 
    '{841A7317-3805-518B-C2EA-AD224CB4AF84}': 'SDP Physical Disk',
    '{17F4D97B-F26A-5E79-3A82-90040A47D13D}': 'SDP Volume Provider', 
    '{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}': 'VFU',
    '{B6D82AF1-F780-4E17-8077-6CB9AD8A6FC4}': 'Tagged Energy Provider',
    '{97C2CE28-A37B-4920-B1E9-8B76CD341EC5}': 'Undocumented Windows 10 VM info'
}

column_markups = {
    'All Tables': {
        'TimeStamp': {
            'friendly_name': 'SRUM Entry Creation (UTC)',
            'translate': 'OLE',
        },
        'AppId': {
            'friendly_name': 'Application/Process',
            'translate': 'APPID',
            'width': '100'
        },
        'UserId': {
            'friendly_name': 'User Information',
            'translate': 'SID',
            'width': '60'
        },
        'EndTime': {
            'translate': 'FILE:%Y-%m-%d %H:%M:%S',
            'width': '20'
        },
        'StartTime': {
            'translate': 'FILE:%Y-%m-%d %H:%M:%S',
            'width' : '20'
        },
        'EventTimestamp': {
            'friendly_name': 'Event Time Stamp',
            'translate': 'FILE:%Y-%m-%d %H:%M:%S',
            'width' : '20'
        },
        'ConnectStartTime': {
            'translate': 'FILE:%Y-%m-%d %H:%M:%S',
            'width' : '20'
        },
        'ActiveAcTime': {
            'translate': 'seconds'
        },
        'CsAcTime': {
            'translate': 'seconds'
        },
        'ActiveDcTime': {
            'translate': 'seconds'
        },
        'CsDcTime': {
            'translate': 'seconds'
        },
        'ActiveDischargeTime': {
            'translate': 'seconds'
        },
        'CsDischargeTime': {
            'translate': 'seconds'
        },
        'InterfaceLuid': { 
            'friendly_name': 'Interface',
            'translate': 'interface_types',
            'width' : '25'
        },
        'L2ProfileId': {
            'friendly_name': 'Profile',
            'translate': 'network_interface',
            'width' : '25'
        },
        'AutoIncId': {
            'friendly_name': 'Srum ID Number'

        },
        'ForegroundCycleTime': {
            'friendly_name': 'CPU time in Forground'
        },
        'BackgroundCycleTime': {
            'friendly_name': 'CPU time in background'
        },
        'Flags': {
            'friendly_name': 'Flags (BinaryData)'
        },
        'ChargeLevel': {
            'friendly_name': 'Battery Level'
        },
        'L2ProfileFlags': {
            'friendly_name': 'Profile Flags'
        },
        'BytesSent': {
            'friendly_name': 'Bytes Sent'
        },
        'BytesRecvd': {
            'friendly_name': 'Bytes Received'
        }
    },
    'Energy Usage': {
        # Example override (optional, adjust as needed)
        'Percentage Charge': {
            'friendly_name': 'Charge Percentage',
            'formula': '=I#ROW_NUM#/G#ROW_NUM#',
            'style': "percentage-green" 
        }
    }
}


interface_types = {
    133: "IF_TYPE_CES",
    132: "IF_TYPE_COFFEE",
    131: "IF_TYPE_TUNNEL",
    130: "IF_TYPE_A12MPPSWITCH",
    137: "IF_TYPE_L3_IPXVLAN",
    136: "IF_TYPE_L3_IPVLAN",
    135: "IF_TYPE_L2_VLAN",
    134: "IF_TYPE_ATM_SUBINTERFACE",
    139: "IF_TYPE_MEDIAMAILOVERIP",
    138: "IF_TYPE_DIGITALPOWERLINE",
    24: "IF_TYPE_SOFTWARE_LOOPBACK",
    25: "IF_TYPE_EON",
    26: "IF_TYPE_ETHERNET_3MBIT",
    27: "IF_TYPE_NSIP",
    20: "IF_TYPE_BASIC_ISDN",
    21: "IF_TYPE_PRIMARY_ISDN",
    22: "IF_TYPE_PROP_POINT2POINT_SERIAL",
    23: "IF_TYPE_PPP",
    28: "IF_TYPE_SLIP",
    29: "IF_TYPE_ULTRA",
    4: "IF_TYPE_DDN_X25",
    8: "IF_TYPE_ISO88024_TOKENBUS",
    119: "IF_TYPE_LAP_F",
    120: "IF_TYPE_V37",
    121: "IF_TYPE_X25_MLP",
    122: "IF_TYPE_X25_HUNTGROUP",
    123: "IF_TYPE_TRANSPHDLC",
    124: "IF_TYPE_INTERLEAVE",
    125: "IF_TYPE_FAST",
    126: "IF_TYPE_IP",
    127: "IF_TYPE_DOCSCABLE_MACLAYER",
    128: "IF_TYPE_DOCSCABLE_DOWNSTREAM",
    129: "IF_TYPE_DOCSCABLE_UPSTREAM",
    118: "IF_TYPE_HDLC",
    59: "IF_TYPE_AFLANE_8023",
    58: "IF_TYPE_FRAMERELAY_INTERCONNECT",
    55: "IF_TYPE_IEEE80212",
    54: "IF_TYPE_PROP_MULTIPLEXOR",
    57: "IF_TYPE_HIPPIINTERFACE",
    56: "IF_TYPE_FIBRECHANNEL",
    51: "IF_TYPE_SONET_VT",
    50: "IF_TYPE_SONET_PATH",
    53: "IF_TYPE_PROP_VIRTUAL",
    52: "IF_TYPE_SMDS_ICIP",
    115: "IF_TYPE_ISO88025_FIBER",
    114: "IF_TYPE_IPOVER_ATM",
    88: "IF_TYPE_ARAP",
    89: "IF_TYPE_PROP_CNLS",
    111: "IF_TYPE_STACKTOSTACK",
    110: "IF_TYPE_IPOVER_CLAW",
    113: "IF_TYPE_MPC",
    112: "IF_TYPE_VIRTUALIPADDRESS",
    82: "IF_TYPE_DS0_BUNDLE",
    83: "IF_TYPE_BSC",
    80: "IF_TYPE_ATM_LOGICAL",
    81: "IF_TYPE_DS0",
    86: "IF_TYPE_ISO88025R_DTR",
    87: "IF_TYPE_EPLRS",
    84: "IF_TYPE_ASYNC",
    85: "IF_TYPE_CNR",
    3: "IF_TYPE_HDH_1822",
    7: "IF_TYPE_IS088023_CSMACD",
    108: "IF_TYPE_PPPMULTILINKBUNDLE",
    109: "IF_TYPE_IPOVER_CDLC",
    102: "IF_TYPE_VOICE_FXS",
    103: "IF_TYPE_VOICE_ENCAP",
    100: "IF_TYPE_VOICE_EM",
    101: "IF_TYPE_VOICE_FXO",
    106: "IF_TYPE_ATM_FUNI",
    107: "IF_TYPE_ATM_IMA",
    104: "IF_TYPE_VOICE_OVERIP",
    105: "IF_TYPE_ATM_DXI",
    39: "IF_TYPE_SONET",
    38: "IF_TYPE_MIO_X25",
    33: "IF_TYPE_RS232",
    32: "IF_TYPE_FRAMERELAY",
    31: "IF_TYPE_SIP",
    30: "IF_TYPE_DS3",
    37: "IF_TYPE_ATM",
    36: "IF_TYPE_ARCNET_PLUS",
    35: "IF_TYPE_ARCNET",
    34: "IF_TYPE_PARA",
    60: "IF_TYPE_AFLANE_8025",
    61: "IF_TYPE_CCTEMUL",
    62: "IF_TYPE_FASTETHER",
    63: "IF_TYPE_ISDN",
    64: "IF_TYPE_V11",
    65: "IF_TYPE_V36",
    66: "IF_TYPE_G703_64K",
    67: "IF_TYPE_G703_2MB",
    68: "IF_TYPE_QLLC",
    69: "IF_TYPE_FASTETHER_FX",
    2: "IF_TYPE_REGULAR_1822",
    6: "IF_TYPE_ETHERNET_CSMACD",
    99: "IF_TYPE_MYRINET",
    98: "IF_TYPE_ISO88025_CRFPRINT",
    91: "IF_TYPE_TERMPAD",
    90: "IF_TYPE_HOSTPAD",
    93: "IF_TYPE_X213",
    92: "IF_TYPE_FRAMERELAY_MPI",
    95: "IF_TYPE_RADSL",
    94: "IF_TYPE_ADSL",
    97: "IF_TYPE_VDSL",
    96: "IF_TYPE_SDSL",
    11: "IF_TYPE_STARLAN",
    10: "IF_TYPE_ISO88026_MAN",
    13: "IF_TYPE_PROTEON_80MBIT",
    12: "IF_TYPE_PROTEON_10MBIT",
    15: "IF_TYPE_FDDI",
    14: "IF_TYPE_HYPERCHANNEL",
    17: "IF_TYPE_SDLC",
    16: "IF_TYPE_LAP_B",
    19: "IF_TYPE_E1",
    18: "IF_TYPE_DS1",
    117: "IF_TYPE_GIGABITETHERNET",
    116: "IF_TYPE_TDLC",
    48: "IF_TYPE_MODEM",
    49: "IF_TYPE_AAL5",
    46: "IF_TYPE_HSSI",
    47: "IF_TYPE_HIPPI",
    44: "IF_TYPE_FRAMERELAY_SERVICE",
    45: "IF_TYPE_V35",
    42: "IF_TYPE_LOCALTALK",
    43: "IF_TYPE_SMDS_DXI",
    40: "IF_TYPE_X25_PLE",
    41: "IF_TYPE_ISO88022_LLC",
    1: "IF_TYPE_OTHER",
    5: "IF_TYPE_RFC877_X25",
    9: "IF_TYPE_ISO88025_TOKENRING",
    144: "IF_TYPE_IEEE1394",
    145: "IF_TYPE_RECEIVE_ONLY",
    142: "IF_TYPE_IPFORWARD",
    143: "IF_TYPE_MSDSL",
    140: "IF_TYPE_DTM",
    141: "IF_TYPE_DCN",
    77: "IF_TYPE_LAP_D",
    76: "IF_TYPE_ISDN_U",
    75: "IF_TYPE_ISDN_S",
    74: "IF_TYPE_DLSW",
    73: "IF_TYPE_ESCON",
    72: "IF_TYPE_IBM370PARCHAN",
    71: "IF_TYPE_IEEE80211",
    70: "IF_TYPE_CHANNEL",
    79: "IF_TYPE_RSRB",
    78: "IF_TYPE_IPSWITCH",
}


ads = itertools.cycle([
    "To learn how SRUM and other artifacts can enhance your forensics investigations check out SANS Windows Forensic Analysis FOR500.\n",
    "Yogesh Khatri made this tool possible. Its all based on his original research and he contributes to this project! Thanks for the support Yogesh. \n",
    "Information from the SOFTWARE hive is added to your config file. There you can customize and extend it.\n",
    "Consider renaming wireless network names and user accounts in the configuration file so they stand out!\n",
    "My class SANS SEC573 Automating Infosec with Python teaches you to develop Forensics and Incident Response tools!\n",
    "Add your Domain (investigation) specific User SIDS to known_sids in the configuration file!\n",
    "Set the dirty_words in the configuration file! NOTE: Dirty words significantly impact performance\n",
    "Do you know how to code in Python?  Prove it with the GPYC Certification!\n",
    "Try 'srum_dump.exe -e pyesedb' to change the engine used to extract the data. Different engines retrieve a different number of records. (Don't shoot the messenger.)\n",
    "Want CSV files instead of XLSX?  Try 'srum_dump.exe -f csv' To create a folder full of CSV files.\n",
    "This program was written by Twitter:@markbaggett because @ovie said so. Thanks @donaldjwilliam5!\n"
])


def BinarySIDtoStringSID(sid_str, sid_lookups=None):
    """Converts a binary SID to its string representation."""
    #Original form Source: https://github.com/google/grr/blob/master/grr/parsers/wmi_parser.py
    """Converts a binary SID to its string representation.
     https://msdn.microsoft.com/en-us/library/windows/desktop/aa379597.aspx
    The byte representation of an SID is as follows:
      Offset  Length  Description
      00      01      revision
      01      01      sub-authority count
      02      06      authority (big endian)
      08      04      subauthority #1 (little endian)
      0b      04      subauthority #2 (little endian)
      ...
    Args:
      sid: A byte array.
    Returns:
      SID in string form.
    Raises:
      ValueError: If the binary SID is malformed.
    """
    logger.debug(f"Called BinarySIDtoStringSID with sid_str length: {len(sid_str) if sid_str else 0}, sid_lookups: {'Provided' if sid_lookups else 'Default'}")
    sid_string_representation = "" # Initialize
    sid_name = 'unknown'
    try:
        if not sid_str or sid_str == 'Empty':
            logger.debug("sid_str is empty, returning empty string.")
            return ""
        if sid_lookups is None:
            logger.debug("Using default known_sids for lookup.")
            sid_lookups = known_sids
        sid = sid_str # Assuming sid_str is already bytes
        str_sid_components = [sid[0]] # Revision

        # Now decode the 48-byte portion (Authority + Subauthorities)
        if len(sid) >= 8:
            subauthority_count = sid[1]
            # Authority (6 bytes, big-endian)
            identifier_authority = struct.unpack(">H", sid[2:4])[0] # First 2 bytes
            identifier_authority <<= 32
            identifier_authority |= struct.unpack(">L", sid[4:8])[0] # Last 4 bytes
            str_sid_components.append(identifier_authority)

            # Subauthorities (4 bytes each, little-endian)
            start = 8
            for i in range(subauthority_count):
                authority = sid[start:start + 4]
                if not authority:
                    logger.warning(f"SID component {i} is missing.")
                    break
                if len(authority) < 4:
                    err_msg = (f"In binary SID, component {i} has been truncated. "
                               f"Expected 4 bytes, found {len(authority)}: ({authority})")
                    logger.error(err_msg)
                    raise ValueError(err_msg)
                str_sid_components.append(struct.unpack("<L", authority)[0])
                start += 4

            # Construct the string representation (only if components were added)
            if len(str_sid_components) > 1:
                 sid_string_representation = "S-%s" % ("-".join([str(x) for x in str_sid_components]))
                 sid_name = sid_lookups.get(sid_string_representation, 'unknown')

        else:
             logger.warning(f"SID length ({len(sid)}) is less than 8 bytes, cannot decode authority/subauthorities.")
             # Attempt to use the raw input as the key if it's short
             sid_string_representation = str(sid_str) # Fallback
             sid_name = sid_lookups.get(sid_string_representation, 'unknown')


        result = "{} ({})".format(sid_string_representation, sid_name)
        logger.debug(f"Successfully converted SID to: {result}")
        return result

    except Exception as e:
        logger.exception(f"Error converting binary SID: {e}")
        return f"Error converting SID: {sid_str}"


def blob_to_string(binblob):
    """Takes in a binary blob hex characters and does its best to convert it to a readable string.
       Works great for UTF-16 LE, UTF-16 BE, ASCII like data. Otherwise return it as hex.
    """
    logger.debug(f"Called blob_to_string with binblob type: {type(binblob)}, length: {len(binblob) if hasattr(binblob, '__len__') else 'N/A'}")
    
    if not binblob:  #Easy-peazy.. if binblob blank
       return ""
    
    result_blob = binblob # Default to original if conversion fails
    try:
        if isinstance(binblob, str):
            logger.debug("Input is string, encoding with null byte prefix.")
            binblob = b"\x00" + binblob.encode()

        # Attempt to decode from hex if it looks like hex
        try:
            # Basic check if it looks like hex (even length, hex chars)
            if binblob and len(binblob) % 2 == 0 and all(c in b'0123456789abcdefABCDEF' for c in binblob):
                 chrblob = codecs.decode(binblob, "hex")
                 logger.debug("Decoded binblob from hex.")
            else:
                 chrblob = binblob
                 logger.debug("Input doesn't look like hex, treating as raw bytes.")
        except Exception as hex_decode_error:
            logger.exception(f"Failed to decode binblob from hex, treating as raw bytes: {hex_decode_error}")
            chrblob = binblob # Fallback to original bytes

        # Attempt string decoding
        decoded = False
        if re.match(b'^(?:[^\x00]\x00)+', chrblob): # UTF-16 LE pattern
            try:
                result_blob = chrblob.decode("utf-16-le").strip("\x00")
                logger.debug("Decoded as UTF-16 LE.")
                decoded = True
            except Exception as utf16le_error:
                logger.exception(f"Potential UTF-16 LE pattern detected, but decoding failed: {utf16le_error}")
        elif re.match(b'^(?:\x00[^\x00])+', chrblob): # UTF-16 BE pattern
            try:
                result_blob = chrblob.decode("utf-16-be").strip("\x00")
                logger.debug("Decoded as UTF-16 BE.")
                decoded = True
            except Exception as utf16be_error:
                logger.exception(f"Potential UTF-16 BE pattern detected, but decoding failed: {utf16be_error}")

        if not decoded: # Try latin1 as a fallback if not UTF-16
            try:
                result_blob = chrblob.decode("latin1").strip("\x00")
                logger.debug("Decoded as latin1.")
            except Exception as latin1_error:
                logger.exception(f"Failed to decode as latin1: {latin1_error}. Falling back to hex representation of original bytes.")
                # Final fallback: return hex representation of original bytes if all decoding fails
                result_blob = binblob.hex() if isinstance(binblob, bytes) else str(binblob)

    except Exception as e:
        logger.exception(f"Error in blob_to_string: {e}")
        # Ensure we return something, preferably hex of original if possible
        try:
            result_blob = binblob.hex() if isinstance(binblob, bytes) else str(binblob)
        except:
            result_blob = str(binblob) # Absolute fallback

    logger.debug(f"Returning blob as string: {result_blob[:100]}...") # Log truncated result
    return result_blob


def ole_timestamp(binblob):
    """converts a hex encoded OLE time stamp to a time string"""
    logger.debug(f"Called ole_timestamp with binblob type: {type(binblob)}")
    """converts a hex encoded OLE time stamp to a time string"""
    if isinstance(binblob, datetime):
        logger.debug("Input is already datetime object, returning directly.")
        return binblob
    dt = f"Invalid OLE Timestamp: {binblob}" # Default error message
    try:
        # Ensure binblob is bytes and has the correct length (8 bytes for double)
        if isinstance(binblob, bytes) and len(binblob) == 8:
            ole_float = struct.unpack("<d", binblob)[0]
            td, ts_part = str(ole_float).split(".")
            # Handle potential precision issues with float conversion
            ts_float = float("0." + ts_part)
            # Calculate seconds carefully
            seconds_part = round(86400 * ts_float) # Round to nearest second
            dt = datetime(1899, 12, 30, 0, 0, 0) + timedelta(days=int(td), seconds=seconds_part)
            logger.debug(f"Successfully converted OLE timestamp to: {dt}")
        else:
             logger.warning(f"Input binblob is not 8 bytes or not bytes type: type={type(binblob)}, len={len(binblob) if hasattr(binblob, '__len__') else 'N/A'}")
             dt = f"Invalid input for OLE timestamp (expected 8 bytes): {binblob}"

    except Exception as e:
        logger.exception(f"Error converting OLE timestamp: {e}. Input was: {binblob}")
        dt = f"Conversion Error: {e}" # More specific error
    return dt


def file_timestamp(binblob):
    """converts a hex encoded windows file time stamp to a time string"""
    logger.debug(f"Called file_timestamp with binblob: {binblob}")
    """converts a hex encoded windows file time stamp to a time string"""
    dt = f"Invalid FILETIME: {binblob}" # Default error message
    try:
        # FILETIME is a 64-bit integer (microseconds / 10 since 1601-01-01)
        if isinstance(binblob, int):
            # Ensure it's a plausible value (e.g., positive)
            if binblob >= 0:
                dt = datetime(1601, 1, 1, 0, 0, 0, tzinfo=timezone.utc) + timedelta(microseconds=binblob / 10)
                # Convert to local time if needed, or keep as UTC
                # dt = dt.astimezone() # Example: convert to local timezone
                dt = dt.replace(tzinfo=None)
                logger.debug(f"Successfully converted FILETIME timestamp to: {dt}")
            else:
                logger.warning(f"Input binblob is negative: {binblob}")
                dt = f"Invalid FILETIME (negative value): {binblob}"
        else:
            logger.warning(f"Input binblob is not an integer: type={type(binblob)}")
            dt = f"Invalid input for FILETIME (expected int): {binblob}"
    except Exception as e:
        logger.exception(f"Error converting FILETIME timestamp: {e}. Input was: {binblob}")
        dt = f"Conversion Error: {e}"
    return dt

def load_registry_sids(reg_file):
    """Given Software hive find SID usernames"""
    logger.debug(f"Called load_registry_sids with reg_file: {reg_file}")
    """Given Software hive find SID usernames"""
    sids = {}
    profile_key = r"Microsoft\Windows NT\CurrentVersion\ProfileList"
    tgt_value = "ProfileImagePath"
    try:
        logger.debug(f"Attempting to open registry file: {reg_file}")
        reg_handle = Registry.Registry(reg_file)
        logger.debug(f"Attempting to open key: {profile_key}")
        key_handle = reg_handle.open(profile_key)
        logger.debug(f"Iterating through subkeys of {profile_key}")
        for eachsid in key_handle.subkeys():
            try:
                sid_name = eachsid.name()
                logger.debug(f"Processing SID key: {sid_name}")
                profile_path_value = eachsid.value(tgt_value)
                sids_path = profile_path_value.value()
                username = sids_path.split("\\")[-1]
                sids[sid_name] = username
                logger.debug(f"Found SID: {sid_name} -> User: {username}")
            except Registry.RegistryValueNotFoundException:
                logger.warning(f"Value '{tgt_value}' not found for SID {sid_name}")
            except Exception as sid_ex:
                 logger.exception(f"Error processing SID subkey {eachsid.name()}: {sid_ex}")
    except Registry.RegistryKeyNotFoundException:
        logger.exception(f"Registry key '{profile_key}' not found in {reg_file}.")
        return {}
    except Exception as e:
        logger.exception(f"Failed to load registry SIDs from {reg_file}: {e}")
        return {}

    logger.debug(f"Finished loading registry SIDs. Found {len(sids)} SIDs.")
    return sids


def load_srum_table_names(reg_file):
    """
    Given a Software hive path, extracts SRUM Extension GUIDs along with their names and descriptions.

    Args:
        reg_file (str): Path to the SOFTWARE registry hive file.

    Returns:
        dict: Combines known_tables above with any defined in the software registry hive
    """
    logger.debug(f"Called load_srum_table_names with reg_file: {reg_file}")
    srum_data = {}
    srum_key_path = r"Microsoft\Windows NT\CurrentVersion\SRUM\Extensions"
    name_value = "(default)"

    try:
        logger.debug(f"Attempting to open registry file: {reg_file}")
        reg_handle = Registry.Registry(reg_file)
        logger.debug(f"Attempting to open key: {srum_key_path}")
        key_handle = reg_handle.open(srum_key_path)
        logger.debug(f"Iterating through subkeys of {srum_key_path}")

        for ext_key in key_handle.subkeys():
            try:
                guid = ext_key.name()
                logger.debug(f"Processing SRUM extension key: {guid}")

                try:
                    name = ext_key.value(name_value).value()
                    known_tables[guid] = name
                    logger.debug(f"Found Name for {guid}: {name}")
                except Registry.RegistryValueNotFoundException:
                    logger.warning(f"Value '{name_value}' not found for GUID {guid}")
            except Exception as guid_ex:
                logger.exception(f"Error processing SRUM GUID subkey {ext_key.name()}: {guid_ex}")
        return known_tables
    except Registry.RegistryKeyNotFoundException:
        logger.exception(f"Registry key '{srum_key_path}' not found in {reg_file}.")
        return {}
    except Exception as e:
        logger.exception(f"Failed to load SRUM table names from {reg_file}: {e}")
        return {}

    logger.debug(f"Finished loading SRUM table names. Found {len(srum_data)} entries.")
    return srum_data


def load_interfaces(reg_file):
    """Loads the names of the wireless networks from the software registry hive"""
    logger.debug(f"Called load_interfaces with reg_file: {reg_file}")
    """Loads the names of the wireless networks from the software registry hive"""
    profile_lookup = {}
    try:
        logger.debug(f"Attempting to open registry file: {reg_file}")
        reg_handle = Registry.Registry(reg_file)
    except Exception as e:
        # Keep original print statements but also log
        err_msg = f"Could not open the specified SOFTWARE registry key: {reg_file}. It is usually located in \\Windows\\system32\\config. This is an optional value."
        print(err_msg)
        print(f"WARNING : {str(e)}")
        logger.exception(err_msg + f" Error: {e}")
        return {}

    try:
        interfaces_key_path = 'Microsoft\\WlanSvc\\Interfaces'
        logger.debug(f"Attempting to open key: {interfaces_key_path}")
        int_keys = reg_handle.open(interfaces_key_path)
    except Registry.RegistryKeyNotFoundException:
         warn_msg = "Wireless interfaces key ('Microsoft\\WlanSvc\\Interfaces') not found in this registry file."
         logger.warning(warn_msg)
         return {}
    except Exception as e:
        err_msg = "Error opening wireless interfaces key."
        logger.exception(err_msg + f" Error: {e}")
        return {}

    logger.debug("Iterating through interface subkeys.")
    for eachinterface in int_keys.subkeys():
        interface_name = eachinterface.name()
        logger.debug(f"Processing interface: {interface_name}")
        try:
            profiles_key = eachinterface.subkey("Profiles")
            logger.debug(f"Processing 'Profiles' subkey for interface {interface_name}")
            for eachprofile in profiles_key.subkeys():
                profile_name = eachprofile.name()
                logger.debug(f"Processing profile: {profile_name}")
                try:
                    # Find ProfileIndex
                    profileid_values = [x.value() for x in list(eachprofile.values()) if x.name() == "ProfileIndex"]
                    if not profileid_values:
                        logger.warning(f"'ProfileIndex' not found for profile {profile_name} under interface {interface_name}")
                        continue
                    profileid = profileid_values[0]
                    logger.debug(f"Found ProfileIndex: {profileid}")

                    # Look for network name in MetaData
                    metadata_key = eachprofile.subkey("MetaData")
                    metadata_values = list(metadata_key.values())
                    network_name = None
                    for eachvalue in metadata_values:
                        # Adjusting logic slightly - often the name is in 'Description' or similar, not just hints
                        # Let's prioritize Description, then fall back to hints or other likely fields
                        # This part might need refinement based on actual registry structures observed
                        if eachvalue.name() == "Description": # Check common fields first
                             network_name = eachvalue.value()
                             logger.debug(f"Found network name in 'Description': {network_name}")
                             break
                        elif eachvalue.name() in ["Channel Hints", "Band Channel Hints"]: # Fallback to hints
                            channelhintraw = eachvalue.value()
                            if isinstance(channelhintraw, bytes) and len(channelhintraw) > 4:
                                hintlength = struct.unpack("<I", channelhintraw[0:4])[0] # Assuming Little Endian length
                                # Check if length is plausible
                                if 4 + hintlength <= len(channelhintraw):
                                     name_bytes = channelhintraw[4:hintlength + 4]
                                     try:
                                         # Try decoding common encodings
                                         network_name = name_bytes.decode("utf-8").rstrip('\x00')
                                     except UnicodeDecodeError:
                                         try:
                                             network_name = name_bytes.decode("latin1").rstrip('\x00')
                                         except Exception as decode_err:
                                             logger.warning(f"Could not decode network name from hints for profile {profile_name}: {decode_err}")
                                             network_name = f"Undecoded_{profileid}" # Placeholder
                                     logger.debug(f"Found network name in '{eachvalue.name()}': {network_name}")
                                     break # Found name, stop searching metadata
                                else:
                                     logger.warning(f"Implausible length ({hintlength}) in '{eachvalue.name()}' for profile {profile_name}")
                            else:
                                logger.warning(f"'{eachvalue.name()}' value is not bytes or too short for profile {profile_name}")

                    if network_name:
                        profile_lookup[str(profileid)] = network_name
                        logger.info(f"Mapped Profile ID {profileid} to Network Name '{network_name}'")
                    else:
                        logger.warning(f"Could not determine network name for Profile ID {profileid} under interface {interface_name}")

                except Registry.RegistryKeyNotFoundException as profile_ex:
                    logger.warning(f"Subkey 'MetaData' or value 'ProfileIndex' not found for profile {profile_name}: {profile_ex}")
                except Exception as profile_ex:
                    logger.exception(f"Error processing profile {profile_name} under interface {interface_name}: {profile_ex}")

        except Registry.RegistryKeyNotFoundException:
            logger.warning(f"Subkey 'Profiles' not found for interface {interface_name}")
        except Exception as interface_ex:
            logger.exception(f"Error processing interface {interface_name}: {interface_ex}")

    logger.debug(f"Finished loading interfaces. Found {len(profile_lookup)} profiles.")
    return profile_lookup

def load_template_lookups(template_workbook):
    """Load any tabs named lookup-xyz form the template file for lookups of columns with the same format type"""
    logger.debug("Called load_template_lookups")
    """Load any tabs named lookup-xyz form the template file for lookups of columns with the same format type"""
    template_lookups = {}
    try:
        sheet_names = template_workbook.sheetnames # Use .sheetnames for openpyxl >= 2.4
        logger.debug(f"Found sheets: {sheet_names}")
        for each_sheet_name in sheet_names:
            if each_sheet_name.lower().startswith("lookup-"):
                lookupname = each_sheet_name.split("-", 1)[1] # Split only once
                logger.debug(f"Processing lookup sheet: {each_sheet_name} for lookup name: {lookupname}")
                template_sheet = template_workbook[each_sheet_name] # Access sheet by name
                lookup_table = {}
                # Iterate through rows, skipping header if necessary (assuming header is row 1)
                for eachrow in range(1, template_sheet.max_row + 1):
                    try:
                        value = template_sheet.cell(row=eachrow, column=1).value
                        description = template_sheet.cell(row=eachrow, column=2).value
                        if value is not None: # Only add if value is not None
                            lookup_table[value] = description
                            # logger.debug(f"Added lookup: {value} -> {description}") # Can be verbose
                        else:
                            logger.warning(f"Skipping row {eachrow} in sheet {each_sheet_name} due to None value in column 1.")
                    except Exception as row_ex:
                        logger.exception(f"Error processing row {eachrow} in sheet {each_sheet_name}: {row_ex}")
                template_lookups[lookupname] = lookup_table
                logger.info(f"Loaded {len(lookup_table)} entries for lookup '{lookupname}'")
    except Exception as e:
        logger.exception(f"Error loading template lookups: {e}")

    logger.debug(f"Finished loading template lookups. Found {len(template_lookups)} lookup tables.")
    return template_lookups

def load_template_tables(template_workbook):
    """Load template tabs that define the field names and formats for tables found in SRUM"""
    logger.debug("Called load_template_tables")
    """Load template tabs that define the field names and formats for tables found in SRUM"""
    template_tables = {}
    try:
        sheets = template_workbook.sheetnames # Use .sheetnames
        logger.debug(f"Found sheets: {sheets}")
        for each_sheet_name in sheets:
            # Skip lookup sheets
            if each_sheet_name.lower().startswith("lookup-"):
                continue

            logger.debug(f"Processing template sheet: {each_sheet_name}")
            template_sheet = template_workbook[each_sheet_name]

            # Retrieve the name of the ESE table from A1
            ese_template_table = template_sheet.cell(row=1, column=1).value
            if not ese_template_table:
                logger.warning(f"Skipping sheet '{each_sheet_name}' because cell A1 (ESE table name) is empty.")
                continue
            logger.debug(f"ESE Table Name from A1: {ese_template_table}")

            # Retrieve column definitions from rows 2, 3, 4
            template_field = {}
            logger.debug(f"Reading columns for sheet {each_sheet_name} (max_column: {template_sheet.max_column})")
            for eachcolumn in range(1, template_sheet.max_column + 1):
                field_name = template_sheet.cell(row=2, column=eachcolumn).value
                if field_name is None:
                    logger.debug(f"Stopping column read at column {eachcolumn} due to None field name.")
                    break # Stop if we hit an empty column name

                # Get format (row 3), style (row 4), and display value (row 4)
                template_format = template_sheet.cell(row=3, column=eachcolumn).value
                template_style = template_sheet.cell(row=4, column=eachcolumn).style # Note: This gets style object, might need adjustment depending on usage
                template_value = template_sheet.cell(row=4, column=eachcolumn).value

                # Use field_name as display value if template_value is empty
                display_value = template_value if template_value else field_name

                template_field[field_name] = (template_style, template_format, display_value)
                # logger.debug(f"  Column {eachcolumn}: Name='{field_name}', Format='{template_format}', Display='{display_value}'") # Can be verbose

            template_tables[ese_template_table] = (each_sheet_name, template_field)
            logger.info(f"Loaded template for ESE table '{ese_template_table}' from sheet '{each_sheet_name}' with {len(template_field)} columns.")

    except Exception as e:
        logger.exception(f"Error loading template tables: {e}")

    logger.debug(f"Finished loading template tables. Found {len(template_tables)} table definitions.")
    return template_tables

def extract_live_file():
    """Extracts live SRUDB.dat and SOFTWARE hive using esentutl or FGET fallback."""
    logger.debug("Called extract_live_file")
    out1 = b"" # Initialize output variables
    out2 = b""
    tmp_dir = None # Initialize for finally block
    try:
        tmp_dir = tempfile.mkdtemp()
        logger.info(f"Created temporary directory: {tmp_dir}")
        fget_file = pathlib.Path(tmp_dir) / "fget.exe"
        registry_file = pathlib.Path(tmp_dir) / "SOFTWARE"
        extracted_srum = pathlib.Path(tmp_dir) / "srudb.dat"

        # Prefer esentutl if available
        comspec = os.environ.get("COMSPEC")
        esentutl_path = None
        if comspec:
             esentutl_path = pathlib.Path(comspec).parent / "esentutl.exe"

        if esentutl_path and esentutl_path.exists():
            logger.info("Using esentutl.exe for extraction.")
            # Extract SRUM DB
            srum_src = r"c:\windows\system32\sru\srudb.dat"
            cmdline1 = f'"{esentutl_path}" /y "{srum_src}" /vss /d "{extracted_srum}"'
            logger.debug(f"Executing SRUM extraction command: {cmdline1}")
            phandle1 = subprocess.Popen(cmdline1, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out1, err1 = phandle1.communicate()
            logger.debug(f"SRUM extraction stdout: {out1.decode(errors='ignore')}")
            logger.debug(f"SRUM extraction stderr: {err1.decode(errors='ignore')}")

            # Extract SOFTWARE hive
            reg_src = r"c:\windows\system32\config\SOFTWARE"
            cmdline2 = f'"{esentutl_path}" /y "{reg_src}" /vss /d "{registry_file}"'
            logger.debug(f"Executing Registry extraction command: {cmdline2}")
            phandle2 = subprocess.Popen(cmdline2, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out2, err2 = phandle2.communicate()
            logger.debug(f"Registry extraction stdout: {out2.decode(errors='ignore')}")
            logger.debug(f"Registry extraction stderr: {err2.decode(errors='ignore')}")
            out1 += err1 # Combine stdout/stderr for checking
            out2 += err2
        else:
            logger.warning("esentutl.exe not found or COMSPEC not set. Falling back to FGET.exe.")
            fget_url = 'https://github.com/MarkBaggett/srum-dump/raw/master/FGET.exe'
            try:
                logger.debug(f"Downloading FGET.exe from {fget_url}")
                fget_binary = urllib.request.urlopen(fget_url).read()
                logger.debug(f"Writing FGET.exe to {fget_file}")
                fget_file.write_bytes(fget_binary)
            except Exception as download_ex:
                 logger.exception(f"Failed to download or write FGET.exe: {download_ex}")
                 print(f"ERROR: Failed to download FGET.exe: {download_ex}")
                 return None # Cannot proceed without extraction tool

            # Extract SRUM DB with FGET
            srum_src = r"c:\windows\system32\sru\srudb.dat"
            cmdline1 = f'"{fget_file}" -extract "{srum_src}" "{extracted_srum}"'
            logger.debug(f"Executing SRUM extraction command: {cmdline1}")
            phandle1 = subprocess.Popen(cmdline1, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out1, err1 = phandle1.communicate()
            logger.debug(f"SRUM extraction stdout: {out1.decode(errors='ignore')}")
            logger.debug(f"SRUM extraction stderr: {err1.decode(errors='ignore')}")

            # Extract SOFTWARE hive with FGET
            reg_src = r"c:\windows\system32\config\SOFTWARE"
            cmdline2 = f'"{fget_file}" -extract "{reg_src}" "{registry_file}"'
            logger.debug(f"Executing Registry extraction command: {cmdline2}")
            phandle2 = subprocess.Popen(cmdline2, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out2, err2 = phandle2.communicate()
            logger.debug(f"Registry extraction stdout: {out2.decode(errors='ignore')}")
            logger.debug(f"Registry extraction stderr: {err2.decode(errors='ignore')}")
            out1 += err1 # Combine stdout/stderr
            out2 += err2

            # Clean up downloaded FGET
            try:
                logger.debug(f"Deleting downloaded FGET.exe: {fget_file}")
                fget_file.unlink()
            except Exception as unlink_ex:
                logger.warning(f"Could not delete temporary FGET.exe: {unlink_ex}")

    except Exception as e:
        # Log exception and print original message
        err_msg = f"Unable to automatically extract files. Error: {e}"
        print(err_msg)
        print(f"SRUM Output:\n{out1.decode(errors='ignore')}\nRegistry Output:\n{out2.decode(errors='ignore')}")
        logger.exception(err_msg)
        return None
    finally:
        # Attempt to clean up temp dir even if errors occurred
        if tmp_dir and pathlib.Path(tmp_dir).exists():
            try:
                # Be cautious deleting directories, ensure it's the one we created
                # shutil.rmtree(tmp_dir) # Consider using shutil for robust deletion
                # For now, just log that it should be cleaned up manually if needed
                logger.info(f"Temporary directory {tmp_dir} may need manual cleanup if files remain.")
                pass # Avoid auto-deletion for safety unless explicitly required
            except Exception as cleanup_ex:
                logger.warning(f"Failed to clean up temporary directory {tmp_dir}: {cleanup_ex}")


    # Check results
    combined_output = out1 + out2
    if (b"error" in combined_output.lower()) or (b"fail" in combined_output.lower()):
        err_msg = f"ERROR during extraction.\n SRUM Extraction Output: {out1.decode(errors='ignore')}\n Registry Extraction Output: {out2.decode(errors='ignore')}"
        print(err_msg)
        logger.error(err_msg)
        # Check if files were partially created and log
        if not extracted_srum.exists(): logger.error("Extracted SRUM file does not exist.")
        if not registry_file.exists(): logger.error("Extracted Registry file does not exist.")
        return None # Indicate failure
    elif b"success" in out1.lower() and b"success" in out2.lower():
        logger.info(f"Successfully extracted SRUM to {extracted_srum} and Registry to {registry_file}")
        return str(extracted_srum), str(registry_file)
    else:
        # Log uncertainty but still return paths if they exist, as esentutl might not print 'success'
        warn_msg = f"Could not definitively determine success or failure from output.\n SRUM Output: {out1.decode(errors='ignore')}\n Registry Output: {out2.decode(errors='ignore')}"
        print(warn_msg)
        logger.warning(warn_msg)
        if extracted_srum.exists() and registry_file.exists():
             logger.warning("Both extracted files exist, proceeding despite ambiguous output.")
             return str(extracted_srum), str(registry_file)
        else:
             logger.error("Extraction likely failed as one or both output files are missing.")
             if not extracted_srum.exists(): logger.error(f"Missing: {extracted_srum}")
             if not registry_file.exists(): logger.error(f"Missing: {registry_file}")
             return None # Indicate failure
