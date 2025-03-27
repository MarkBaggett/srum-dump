import pathlib
import struct
import os
import tempfile
import urllib.request
import subprocess
import codecs
import re
import itertools

from datetime import datetime, timezone, timedelta
from Registry import Registry


skip_tables = ['MSysObjects', 'MSysObjectsShadow', 'MSysObjids', 'MSysLocales','SruDbIdMapTable', 'SruDbCheckpointTable']

dirty_words = {
    'put a process user or wifi network name here before the colon': 'RED',
    'After the colon put a color in all caps':'BLUE',
    'These dirty words SIGNIFICANTLY impact performance use with caution':'GREEN',
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
    '{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}': 'Application', 
    '{5C8CF1C7-7257-4F13-B223-970EF5939312}': 'Application Timeline', 
    '{DA73FB89-2BEA-4DDC-86B8-6E048C6DA477}': 'Energy Estimator', 
    '{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}': 'Energy Usage', 
    '{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT': 'Energy Usage Long Term', 
    '{DD6636C4-8929-4683-974E-22C046A43763}': 'Network Connectivity', 
    '{973F5D5C-1D90-4944-BE8E-24B94231A174}': 'Network Data', 
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

columns_to_translate = {
    'TimeStamp': 'OLE',
    'AppId': 'APPID',
    'UserId': 'SID',
    'EndTime': 'FILE:%Y-%m-%d %H:%M:%S',
    'EventTimestamp': 'FILE:%Y-%m-%d %H:%M:%S',
    'ActiveAcTime': 'seconds',
    'CsAcTime': 'seconds',
    'ActiveDcTime': 'seconds',
    'CsDcTime': 'seconds',
    'ActiveDischargeTime': 'seconds',
    'CsDischargeTime': 'seconds',
    'InterfaceLuid':'interface_types',
    'L2ProfileId':'network_interface'
}

calculated_columns = {
    'Energy Usage': {'Percentage Charge':'=I#ROW_NUM#/G#ROW_NUM#'}  #Add Percentage charge to Energy Usage with specified function
}

columns_to_rename = {
    "TimeStamp": "SRUM Entry Creation (UTC)",
    "AppId" : "Application/Process",
    "UserId" : "User Information",
    'AutoIncId': 'Srum ID Number', 
    'ForegroundCycleTime': 'CPU time in Forground', 
    'BackgroundCycleTime': 'CPU time in background', 
    'Flags': 'Flags (BinaryData)', 
    'EventTimestamp': 'Event Time Stamp', 
    'ChargeLevel': 'Battery Level', 
    'InterfaceLuid': 'Interface', 
    'L2ProfileId': 'Profile', 
    'L2ProfileFlags': 'Profile Flags', 
    'BytesSent': 'Bytes Sent', 
    'BytesRecvd': 'Bytes Received'
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
    "Consider renaming wireless network names and user accounts in the configuration file so they stand out!\n"
    "My class SANS SEC573 Automating Infosec with Python teaches you to develop Forensics and Incident Response tools!\n",
    "Add your Domain (investigation) specific User SIDS to known_sids in the configuration file!\n",
    "Set the dirty_words in the configuration file! NOTE: Dirty words significantly impact performance\n",
    "Do you know how to code in Python?  Prove it with the GPYC Certification!\n",
    "Try 'srum_dump.exe -e pyesedb' to change the engine used to extract the data. Different engines retrieve a different number of records. (Don't shoot the messenger.)\n",
    "Want CSV files instead of XLSX?  Try 'srum_dump.exe -f csv' To create a folder full of CSV files.\n",
    "This program was written by Twitter:@markbaggett because @ovie said so. Thanks @donaldjwilliam5!\n"
])

def column_friendly_names( original_name):
    #Returns renamed column or original if it was not in the config
    return columns_to_rename.get( original_name, original_name)

def BinarySIDtoStringSID(sid_str, sid_lookups=None):
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
    if not sid_str or sid_str == 'Empty':
        return ""
    if sid_lookups == None:
        sid_lookups = known_sids
    sid = sid_str
    #sid = codecs.decode(sid_str,"hex")
    str_sid_components = [sid[0]]
    # Now decode the 48-byte portion
    if len(sid) >= 8:
        subauthority_count = sid[1]
        identifier_authority = struct.unpack(">H", sid[2:4])[0]
        identifier_authority <<= 32
        identifier_authority |= struct.unpack(">L", sid[4:8])[0]
        str_sid_components.append(identifier_authority)
        start = 8
        for i in range(subauthority_count):
            authority = sid[start:start + 4]
            if not authority:
                break
            if len(authority) < 4:
                raise ValueError("In binary SID '%s', component %d has been truncated. "
                         "Expected 4 bytes, found %d: (%s)",
                         ",".join([str(ord(c)) for c in sid]), i,
                         len(authority), authority)
            str_sid_components.append(struct.unpack("<L", authority)[0])
            start += 4
            sid_str = "S-%s" % ("-".join([str(x) for x in str_sid_components]))
    sid_name = sid_lookups.get(sid_str,'unknown')
    return "{} ({})".format(sid_str,sid_name)

def blob_to_string(binblob):
    """Takes in a binary blob hex characters and does its best to convert it to a readable string.
       Works great for UTF-16 LE, UTF-16 BE, ASCII like data. Otherwise return it as hex.
    """
    if isinstance(binblob, str):
        binblob = b"\x00" + binblob.encode()   
    try:
        chrblob = codecs.decode(binblob,"hex")
    except:
        chrblob = binblob
    try:
        if re.match(b'^(?:[^\x00]\x00)+', chrblob):
            try:
                binblob = chrblob.decode("utf-16-le").strip("\x00")
            except:
                pass
        elif re.match(b'^(?:\x00[^\x00])+', chrblob):
            try:
                binblob = chrblob.decode("utf-16-be").strip("\x00")
            except:
                pass
        else:
            binblob = chrblob.decode("latin1").strip("\x00")
    except:
        binblob = "" if not binblob else codecs.decode(binblob,"latin-1")
    return binblob

def ole_timestamp(binblob):
    """converts a hex encoded OLE time stamp to a time string"""
    if isinstance(binblob, datetime):
        return binblob
    try:
        td,ts = str(struct.unpack("<d",binblob)[0]).split(".")
        dt = datetime(1899,12,30,0,0,0) + timedelta(days=int(td),seconds=86400 * float("0.{}".format(ts)))
    except Exception as e:
        dt = "This field is incorrectly identified as an OLE timestamp in the template."
    return dt

 
def file_timestamp(binblob):
    """converts a hex encoded windows file time stamp to a time string"""
    try:
        dt = datetime(1601,1,1,0,0,0) + timedelta(microseconds=binblob/10)
    except:
        dt = "This field is incorrectly identified as a file timestamp in the template"
    return dt

def load_registry_sids(reg_file):
    """Given Software hive find SID usernames"""
    sids = {}
    profile_key = r"Microsoft\Windows NT\CurrentVersion\ProfileList"
    tgt_value = "ProfileImagePath"
    try:
        reg_handle = Registry.Registry(reg_file)
        key_handle = reg_handle.open(profile_key)
        for eachsid in key_handle.subkeys():
            sids_path = eachsid.value(tgt_value).value()
            sids[eachsid.name()] = sids_path.split("\\")[-1]
    except:
        return {}
    return sids

def load_interfaces(reg_file):
    """Loads the names of the wireless networks from the software registry hive"""
    try:
        reg_handle = Registry.Registry(reg_file)
    except Exception as e:
        print(r"I could not open the specified SOFTWARE registry key. It is usually located in \Windows\system32\config.  This is an optional value.  If you cant find it just dont provide one.")
        print(("WARNING : ", str(e)))
        return {}
    try:
        int_keys = reg_handle.open('Microsoft\\WlanSvc\\Interfaces')
    except Exception as e:
        print("There doesn't appear to be any wireless interfaces in this registry file.")
        print(("WARNING : ", str(e)))
        return {}
    profile_lookup = {}
    for eachinterface in int_keys.subkeys():
        if len(eachinterface.subkeys())==0:
            continue
        for eachprofile in eachinterface.subkey("Profiles").subkeys():
            profileid = [x.value() for x in list(eachprofile.values()) if x.name()=="ProfileIndex"][0]
            metadata = list(eachprofile.subkey("MetaData").values())
            for eachvalue in metadata:
                if eachvalue.name() in ["Channel Hints", "Band Channel Hints"]:
                    channelhintraw = eachvalue.value()
                    hintlength = struct.unpack("I", channelhintraw[0:4])[0]
                    name = channelhintraw[4:hintlength+4] 
                    profile_lookup[str(profileid)] = name.decode(encoding="latin1")
    return profile_lookup

def load_template_lookups(template_workbook):
    """Load any tabs named lookup-xyz form the template file for lookups of columns with the same format type"""
    template_lookups = {}
    for each_sheet in template_workbook.get_sheet_names():
        if each_sheet.lower().startswith("lookup-"):
            lookupname = each_sheet.split("-")[1]
            template_sheet = template_workbook.get_sheet_by_name(each_sheet)
            lookup_table = {}
            for eachrow in range(1,template_sheet.max_row+1):
                value = template_sheet.cell(row = eachrow, column = 1).value
                description = template_sheet.cell(row = eachrow, column = 2).value
                lookup_table[value] = description
            template_lookups[lookupname] = lookup_table
    return template_lookups
    
def load_template_tables(template_workbook):
    """Load template tabs that define the field names and formats for tables found in SRUM"""
    template_tables = {}    
    sheets = template_workbook.get_sheet_names()
    for each_sheet in sheets:
        #open the first sheet in the template
        template_sheet = template_workbook.get_sheet_by_name(each_sheet)
        #retieve the name of the ESE table to populate the sheet with from A1
        ese_template_table = template_sheet.cell(row=1,column=1).value
        #retrieve the names of the ESE table columns and cell styles from row 2 and format commands from row 3 
        template_field = {}
        #Read the first Row B & C in the template into lists so we know what data we are to extract
        for eachcolumn in range(1,template_sheet.max_column+1):
            field_name = template_sheet.cell(row = 2, column = eachcolumn).value
            if field_name == None:
                break
            template_style = template_sheet.cell(row = 4, column = eachcolumn).style
            template_format = template_sheet.cell(row = 3, column = eachcolumn).value
            template_value = template_sheet.cell(row = 4, column = eachcolumn ).value
            if not template_value:
                template_value= field_name
            template_field[field_name] = (template_style,template_format,template_value)
        template_tables[ese_template_table] = (each_sheet, template_field)
    return template_tables  

def extract_live_file():
    try:
        tmp_dir = tempfile.mkdtemp()
        fget_file = pathlib.Path(tmp_dir) / "fget.exe"
        registry_file = pathlib.Path(tmp_dir) / "SOFTWARE"
        extracted_srum = pathlib.Path(tmp_dir) / "srudb.dat"
        esentutl_path = pathlib.Path(os.environ.get("COMSPEC")).parent / "esentutl.exe"
        if esentutl_path.exists():
            cmdline = r"{} /y c:\\windows\\system32\\sru\\srudb.dat /vss /d {}".format(str(esentutl_path), str(extracted_srum))
            phandle = subprocess.Popen(cmdline, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out1, _ = phandle.communicate()
            cmdline = r"{} /y c:\\windows\\system32\\config\\SOFTWARE /vss /d {}".format(str(esentutl_path), str(registry_file))
            phandle = subprocess.Popen(cmdline, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out2, _ = phandle.communicate()
        else:
            fget_binary = urllib.request.urlopen('https://github.com/MarkBaggett/srum-dump/raw/master/FGET.exe').read()
            fget_file.write_bytes(fget_binary)
            cmdline = r"{} -extract c:\\windows\\system32\\sru\srudb.dat {}".format(str(fget_file), str(extracted_srum))
            phandle = subprocess.Popen(cmdline, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out1, _ = phandle.communicate()
            cmdline = r"{} -extract c:\\windows\\system32\\config\SOFTWARE {}".format(str(fget_file), str(registry_file))
            phandle = subprocess.Popen(cmdline, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out2, _ = phandle.communicate()
            fget_file.unlink()
    except Exception as e:
        print("Unable to automatically extract srum. {}\n{}\n{}".format(str(e), out1.decode(), out2.decode()))
        return None
    if (b"returned error" in out1 + out2) or (b"Init failed" in out1 + out2):
        print("ERROR\n SRUM Extraction: {}\n Registry Extraction {}".format(out1.decode(), out2.decode()))
    elif b"success" in out1.lower() and b"success" in out2.lower():
        return str(extracted_srum), str(registry_file)
    else:
        print("Unable to determine success or failure.", out1.decode(), "\n", out2.decode())
    return None

