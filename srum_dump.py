import os
import sys
import json
import struct
import logging
import datetime

import argparse
from impacket import ese


logger = logging.getLogger(__name__)


def lookup_sid(sid):
    # Returns a common sid https://support.microsoft.com/en-us/kb/243330
    known_sids = {
        'S-1-5-32-545': ' Users', 'S-1-5-32-544': ' Administrators',
        'S-1-5-32-547': ' Power Users', 'S-1-5-32-546': ' Guests',
        'S-1-5-32-569': ' BUILTIN\\Cryptographic Operators',
        'S-1-16-16384': ' System Mandatory Level ',
        'S-1-5-32-551': ' Backup Operators',
        'S-1-16-8192': ' Medium Mandatory Level ', 'S-1-5-80': ' NT Service ',
        'S-1-5-32-548': ' Account Operators',
        'S-1-5-32-561': ' BUILTIN\\Terminal Server License Servers',
        'S-1-5-64-14': ' SChannel Authentication ',
        'S-1-5-32-562': ' BUILTIN\\Distributed COM Users',
        'S-1-5-64-21': ' Digest Authentication ', 'S-1-5-19': ' NT Authority',
        'S-1-3-0': ' Creator Owner', 'S-1-5-80-0': ' All Services ',
        'S-1-5-20': ' NT Authority', 'S-1-5-18': ' Local System',
        'S-1-5-32-552': ' Replicators',
        'S-1-5-32-579': ' BUILTIN\\Access Control Assistance Operators',
        'S-1-16-4096': ' Low Mandatory Level ',
        'S-1-16-12288': ' High Mandatory Level ', 'S-1-2-0': ' Local ',
        'S-1-16-0': ' Untrusted Mandatory Level ', 'S-1-5-3': ' Batch',
        'S-1-5-2': ' Network', 'S-1-5-1': ' Dialup', 'S-1-5-7': ' Anonymous',
        'S-1-5-6': ' Service', 'S-1-5-4': ' Interactive',
        'S-1-5-9': ' Enterprise Domain Controllers', 'S-1-5-8': ' Proxy',
        'S-1-5-32-550': ' Print Operators', 'S-1-0-0': ' Nobody',
        'S-1-5-32-559': ' BUILTIN\\Performance Log Users',
        'S-1-5-32-578': ' BUILTIN\\Hyper-V Administrators',
        'S-1-5-32-549': ' Server Operators', 'S-1-2-1': ' Console Logon ',
        'S-1-3-1': ' Creator Group',
        'S-1-5-32-575': ' BUILTIN\\RDS Remote Access Servers',
        'S-1-3-3': ' Creator Group Server', 'S-1-3-2': ' Creator Owner Server',
        'S-1-5-32-556': ' BUILTIN\\Network Configuration Operators',
        'S-1-5-32-557': ' BUILTIN\\Incoming Forest Trust Builders',
        'S-1-5-32-554': ' BUILTIN\\Pre-Windows 2000 Compatible Access',
        'S-1-5-32-573': ' BUILTIN\\Event Log Readers ',
        'S-1-5-32-576': ' BUILTIN\\RDS Endpoint Servers',
        'S-1-5-83-0': ' NT VIRTUAL MACHINE\\Virtual Machines',
        'S-1-16-28672': ' Secure Process Mandatory Level ',
        'S-1-5-11': ' Authenticated Users', 'S-1-1-0': ' Everyone',
        'S-1-5-32-555': ' BUILTIN\\Remote Desktop Users',
        'S-1-16-8448': ' Medium Plus Mandatory Level ',
        'S-1-5-17': ' This Organization ',
        'S-1-5-32-580': ' BUILTIN\\Remote Management Users',
        'S-1-5-15': ' This Organization ',
        'S-1-5-14': ' Remote Interactive Logon ',
        'S-1-5-13': ' Terminal Server Users', 'S-1-5-12': ' Restricted Code',
        'S-1-5-32-577': ' BUILTIN\\RDS Management Servers',
        'S-1-5-10': ' Principal Self', 'S-1-3': ' Creator Authority',
        'S-1-2': ' Local Authority', 'S-1-1': ' World Authority',
        'S-1-0': ' Null Authority',
        'S-1-5-32-574': ' BUILTIN\\Certificate Service DCOM Access ',
        'S-1-5': ' NT Authority', 'S-1-4': ' Non-unique Authority',
        'S-1-5-32-560': ' BUILTIN\\Windows Authorization Access Group',
        'S-1-16-20480': ' Protected Process Mandatory Level ',
        'S-1-5-64-10': ' NTLM Authentication ',
        'S-1-5-32-558': ' BUILTIN\\Performance Monitor Users'}
    if sid in known_sids:
        return '%s (%s)' % (sid, known_sids.get(sid, sid))
    return sid


def lookup_luid(luidval):
    LUID_interface_types = {
        '133': 'IF_TYPE_CES',
        '132': 'IF_TYPE_COFFEE',
        '131': 'IF_TYPE_TUNNEL',
        '130': 'IF_TYPE_A12MPPSWITCH',
        '137': 'IF_TYPE_L3_IPXVLAN',
        '136': 'IF_TYPE_L3_IPVLAN',
        '135': 'IF_TYPE_L2_VLAN',
        '134': 'IF_TYPE_ATM_SUBINTERFACE',
        '139': 'IF_TYPE_MEDIAMAILOVERIP',
        '138': 'IF_TYPE_DIGITALPOWERLINE',
        '24': 'IF_TYPE_SOFTWARE_LOOPBACK',
        '25': 'IF_TYPE_EON',
        '26': 'IF_TYPE_ETHERNET_3MBIT',
        '27': 'IF_TYPE_NSIP',
        '20': 'IF_TYPE_BASIC_ISDN',
        '21': 'IF_TYPE_PRIMARY_ISDN',
        '22': 'IF_TYPE_PROP_POINT2POINT_SERIAL',
        '23': 'IF_TYPE_PPP',
        '28': 'IF_TYPE_SLIP',
        '29': 'IF_TYPE_ULTRA',
        '4': 'IF_TYPE_DDN_X25',
        '8': 'IF_TYPE_ISO88024_TOKENBUS',
        '119': 'IF_TYPE_LAP_F',
        '120': 'IF_TYPE_V37',
        '121': 'IF_TYPE_X25_MLP',
        '122': 'IF_TYPE_X25_HUNTGROUP',
        '123': 'IF_TYPE_TRANSPHDLC',
        '124': 'IF_TYPE_INTERLEAVE',
        '125': 'IF_TYPE_FAST',
        '126': 'IF_TYPE_IP',
        '127': 'IF_TYPE_DOCSCABLE_MACLAYER',
        '128': 'IF_TYPE_DOCSCABLE_DOWNSTREAM',
        '129': 'IF_TYPE_DOCSCABLE_UPSTREAM',
        '118': 'IF_TYPE_HDLC',
        '59': 'IF_TYPE_AFLANE_8023',
        '58': 'IF_TYPE_FRAMERELAY_INTERCONNECT',
        '55': 'IF_TYPE_IEEE80212',
        '54': 'IF_TYPE_PROP_MULTIPLEXOR',
        '57': 'IF_TYPE_HIPPIINTERFACE',
        '56': 'IF_TYPE_FIBRECHANNEL',
        '51': 'IF_TYPE_SONET_VT',
        '50': 'IF_TYPE_SONET_PATH',
        '53': 'IF_TYPE_PROP_VIRTUAL',
        '52': 'IF_TYPE_SMDS_ICIP',
        '115': 'IF_TYPE_ISO88025_FIBER',
        '114': 'IF_TYPE_IPOVER_ATM',
        '88': 'IF_TYPE_ARAP',
        '89': 'IF_TYPE_PROP_CNLS',
        '111': 'IF_TYPE_STACKTOSTACK',
        '110': 'IF_TYPE_IPOVER_CLAW',
        '113': 'IF_TYPE_MPC',
        '112': 'IF_TYPE_VIRTUALIPADDRESS',
        '82': 'IF_TYPE_DS0_BUNDLE',
        '83': 'IF_TYPE_BSC',
        '80': 'IF_TYPE_ATM_LOGICAL',
        '81': 'IF_TYPE_DS0',
        '86': 'IF_TYPE_ISO88025R_DTR',
        '87': 'IF_TYPE_EPLRS',
        '84': 'IF_TYPE_ASYNC',
        '85': 'IF_TYPE_CNR',
        '3': 'IF_TYPE_HDH_1822',
        '7': 'IF_TYPE_IS088023_CSMACD',
        '108': 'IF_TYPE_PPPMULTILINKBUNDLE',
        '109': 'IF_TYPE_IPOVER_CDLC',
        '102': 'IF_TYPE_VOICE_FXS',
        '103': 'IF_TYPE_VOICE_ENCAP',
        '100': 'IF_TYPE_VOICE_EM',
        '101': 'IF_TYPE_VOICE_FXO',
        '106': 'IF_TYPE_ATM_FUNI',
        '107': 'IF_TYPE_ATM_IMA',
        '104': 'IF_TYPE_VOICE_OVERIP',
        '105': 'IF_TYPE_ATM_DXI',
        '39': 'IF_TYPE_SONET',
        '38': 'IF_TYPE_MIO_X25',
        '33': 'IF_TYPE_RS232',
        '32': 'IF_TYPE_FRAMERELAY',
        '31': 'IF_TYPE_SIP',
        '30': 'IF_TYPE_DS3',
        '37': 'IF_TYPE_ATM',
        '36': 'IF_TYPE_ARCNET_PLUS',
        '35': 'IF_TYPE_ARCNET',
        '34': 'IF_TYPE_PARA',
        '60': 'IF_TYPE_AFLANE_8025',
        '61': 'IF_TYPE_CCTEMUL',
        '62': 'IF_TYPE_FASTETHER',
        '63': 'IF_TYPE_ISDN',
        '64': 'IF_TYPE_V11',
        '65': 'IF_TYPE_V36',
        '66': 'IF_TYPE_G703_64K',
        '67': 'IF_TYPE_G703_2MB',
        '68': 'IF_TYPE_QLLC',
        '69': 'IF_TYPE_FASTETHER_FX',
        '2': 'IF_TYPE_REGULAR_1822',
        '6': 'IF_TYPE_ETHERNET_CSMACD',
        '99': 'IF_TYPE_MYRINET',
        '98': 'IF_TYPE_ISO88025_CRFPRINT',
        '91': 'IF_TYPE_TERMPAD',
        '90': 'IF_TYPE_HOSTPAD',
        '93': 'IF_TYPE_X213',
        '92': 'IF_TYPE_FRAMERELAY_MPI',
        '95': 'IF_TYPE_RADSL',
        '94': 'IF_TYPE_ADSL',
        '97': 'IF_TYPE_VDSL',
        '96': 'IF_TYPE_SDSL',
        '11': 'IF_TYPE_STARLAN',
        '10': 'IF_TYPE_ISO88026_MAN',
        '13': 'IF_TYPE_PROTEON_80MBIT',
        '12': 'IF_TYPE_PROTEON_10MBIT',
        '15': 'IF_TYPE_FDDI',
        '14': 'IF_TYPE_HYPERCHANNEL',
        '17': 'IF_TYPE_SDLC',
        '16': 'IF_TYPE_LAP_B',
        '19': 'IF_TYPE_E1',
        '18': 'IF_TYPE_DS1',
        '117': 'IF_TYPE_GIGABITETHERNET',
        '116': 'IF_TYPE_TDLC',
        '48': 'IF_TYPE_MODEM',
        '49': 'IF_TYPE_AAL5',
        '46': 'IF_TYPE_HSSI',
        '47': 'IF_TYPE_HIPPI',
        '44': 'IF_TYPE_FRAMERELAY_SERVICE',
        '45': 'IF_TYPE_V35',
        '42': 'IF_TYPE_LOCALTALK',
        '43': 'IF_TYPE_SMDS_DXI',
        '40': 'IF_TYPE_X25_PLE',
        '41': 'IF_TYPE_ISO88022_LLC',
        '1': 'IF_TYPE_OTHER',
        '5': 'IF_TYPE_RFC877_X25',
        '9': 'IF_TYPE_ISO88025_TOKENRING',
        '144': 'IF_TYPE_IEEE1394',
        '145': 'IF_TYPE_RECEIVE_ONLY',
        '142': 'IF_TYPE_IPFORWARD',
        '143': 'IF_TYPE_MSDSL',
        '140': 'IF_TYPE_DTM',
        '141': 'IF_TYPE_DCN',
        '77': 'IF_TYPE_LAP_D',
        '76': 'IF_TYPE_ISDN_U',
        '75': 'IF_TYPE_ISDN_S',
        '74': 'IF_TYPE_DLSW',
        '73': 'IF_TYPE_ESCON',
        '72': 'IF_TYPE_IBM370PARCHAN',
        '71': 'IF_TYPE_IEEE80211',
        '70': 'IF_TYPE_CHANNEL',
        '79': 'IF_TYPE_RSRB',
        '78': 'IF_TYPE_IPSWITCH'}
    inttype = struct.unpack('>H6B', format(luidval, '016x').decode('hex'))[0]
    return LUID_interface_types.get(str(inttype), 'Unknown Interface type')


def BinarySIDtoStringSID(sid):
    # Original form Source:
    # https://github.com/google/grr/blob/master/grr/parsers/wmi_parser.py
    '''Converts a binary SID to its string representation.
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
    '''
    if not sid:
        return ''
    str_sid_components = [ord(sid[0])]
    # Now decode the 48-byte portion
    if len(sid) >= 8:
        subauthority_count = ord(sid[1])
        identifier_authority = struct.unpack('>H', sid[2:4])[0]
        identifier_authority <<= 32
        identifier_authority |= struct.unpack('>L', sid[4:8])[0]
        str_sid_components.append(identifier_authority)
        start = 8
        for i in range(subauthority_count):
            authority = sid[start:start + 4]
            if not authority:
                break
            if len(authority) < 4:
                raise ValueError(
                    'In binary SID "%s", component %d has been truncated. '
                    'Expected 4 bytes, found %d: (%s)', ','.join(
                        [str(ord(c)) for c in sid]),
                    i, len(authority),
                    authority)
            str_sid_components.append(struct.unpack('<L', authority)[0])
            start += 4
            sid_str = 'S-%s' % ('-'.join([str(x) for x in str_sid_components]))
    return lookup_sid(sid_str)


def load_lookups(database):
    id_lookup = {}
    try:
        lookup_table = database.openTable('SruDbIdMapTable')
    except Exception:
        raise RuntimeError('failed to lookup id table')

    while True:
        try:
            rec_entry = database.getNextRow(lookup_table)
        except Exception:
            logger.warning('failed to load corrupt record from SruDbIdMapTable')
            continue

        if rec_entry is None:
            return id_lookup

        if rec_entry['IdType'] == 0:
            proc_blob = 'None' if not rec_entry['IdBlob'] else unicode(
                rec_entry['IdBlob'].decode('hex'), 'utf-16-le').strip('\x00')
            id_lookup[rec_entry['IdIndex']] = proc_blob

        elif rec_entry['IdType'] == 1:
            id_lookup[rec_entry['IdIndex']] = unicode(
                rec_entry['IdBlob'].decode('hex'),
                'utf-16-le').strip('\x00')

        elif rec_entry['IdType'] == 2:
            id_lookup[rec_entry['IdIndex']] = unicode(
                rec_entry['IdBlob'].decode('hex'),
                'utf-16-le').strip('\x00')

        elif rec_entry['IdType'] == 3:
            user_blob = 'None' if not rec_entry['IdBlob'] else BinarySIDtoStringSID(
                rec_entry['IdBlob'].decode('hex'))
            id_lookup[rec_entry['IdIndex']] = user_blob

        else:
            logger.warning('unknown entry type in SruDbIdMapTable')

    return id_lookup


TABLE_NAMES = {
    '{973F5D5C-1D90-4944-BE8E-24B94231A174}': 'Network Usage',
    '{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}': 'Application Resource Usage',
    '{DD6636C4-8929-4683-974E-22C046A43763}': 'Network Connections',
    '{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}': 'Push Notification Data',
    '{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT': 'Energy Usage (Long Term)',
    '{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}': 'Energy Usage',
    '{97C2CE28-A37B-4920-B1E9-8B76CD341EC5}': 'unknown',
}


def get_srum_tables(ese_db):
    for tablename in ese_db._ESENT_DB__tables.keys():
        if tablename.startswith('{'):
            yield tablename


def parse_ole_timestamp(n):
    # converts a hex encoded OLE time stamp to a time string
    # TODO: this doesn't look right
    ts = struct.unpack('>d', struct.pack('>Q', n))[0]
    dt = datetime.datetime(1899, 12, 30, 0, 0, 0) + datetime.timedelta(days=ts)
    return dt.isoformat('T') + 'Z'


def parse_file_timestamp(n):
    # converts a hex encoded windows file time stamp to a time string
    dt = datetime.datetime(1601, 1, 1, 0, 0, 0) + datetime.timedelta(microseconds=n / 10)
    return dt.isoformat('T') + 'Z'


def parse_binary(hx):
    return hx


PARSERS = {
    'AutoIncId': int,
    'TimeStamp': parse_ole_timestamp,

    'L2ProfileId': str,
    'InterfaceLuid': lookup_luid,

    'ConnectStartTime': parse_file_timestamp,
    'EventTimestamp': parse_file_timestamp,
    'BinaryData': parse_binary,
}


def parse_entry(ids, name, value):
    if name in PARSERS:
        return PARSERS[name](value)
    elif name.lower().endswith('sid'):
        sid = ids.get(value, value)
        return lookup_sid(sid)
    elif name.lower().endswith('id'):
        return ids.get(value, value)
    else:
        return value


def parse_table(ese_db, id_table, tablename):
    ese_table = ese_db.openTable(tablename)
    if not ese_table:
        logger.warning('failed to find table: %s', tablename, exc_info=True)
        raise RuntimeError('failed to find table')

    while True:
        item = {
            'table_name':  tablename,
            'table_purpose': TABLE_NAMES.get(tablename, 'unknown purpose'),
        }

        try:
            ese_row = ese_db.getNextRow(ese_table)
        except Exception:
            logger.warning('skipping corrupt row...')
            continue

        if ese_row is None:
            break

        for name, value in ese_row.items():
            try:
                v = parse_entry(id_table, name, value)
            except Exception:
                logger.warning('failed to parse value: %s %s', name, value)
            else:
                item[name] = v

        yield item


def main(argv):
    parser = argparse.ArgumentParser(description='Parse artifacts from a SRUM database')
    parser.add_argument('srum', help='the .dat file to analyze')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable debug logging')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Disable all output but errors')
    args = parser.parse_args(args=argv[1:])

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    elif args.quiet:
        logging.basicConfig(level=logging.ERROR)
    else:
        logging.basicConfig(level=logging.INFO)

    if not os.path.exists(args.srum):
        logger.error('.dat file not found')
        return -1

    try:
        ese_db = ese.ESENT_DB(args.srum)
    except Exception:
        logger.error('failed to open .dat file', exc_info=True)
        return -2

    id_table = load_lookups(ese_db)
    for tablename in get_srum_tables(ese_db):
        logger.info('parsing table: %s (%s)', tablename, TABLE_NAMES.get(tablename, 'unknown purpose'))
        for item in parse_table(ese_db, id_table, tablename):
            print(json.dumps(item))


if __name__ == '__main__':
    sys.exit(main(sys.argv[:]))
