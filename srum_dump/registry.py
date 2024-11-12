import struct
from Registry import Registry

class RegistryHandler:
    def __init__(self, registry_file, template_lookups):
        self.registry_file = registry_file
        self.template_lookups = template_lookups
        self.sids = {}
        self.interfaces = {}

    def load_registry_sids(self):
        profile_key = r"Microsoft\Windows NT\CurrentVersion\ProfileList"
        tgt_value = "ProfileImagePath"
        try:
            reg_handle = Registry.Registry(self.registry_file)
            key_handle = reg_handle.open(profile_key)
            for eachsid in key_handle.subkeys():
                sids_path = eachsid.value(tgt_value).value()
                self.sids[eachsid.name()] = sids_path.split("\\")[-1]
        except:
            return {}

    def load_interfaces(self):
        try:
            reg_handle = Registry.Registry(self.registry_file)
        except Exception as e:
            print("I could not open the specified SOFTWARE registry key. It is usually located in \Windows\system32\config.  This is an optional value.  If you cant find it just dont provide one.")
            print("WARNING :", str(e))
            return {}
        try:
            int_keys = reg_handle.open('Microsoft\\WlanSvc\\Interfaces')
        except Exception as e:
            print("There doesn't appear to be any wireless interfaces in this registry file.")
            print("WARNING :", str(e))
            return {}

        for eachinterface in int_keys.subkeys():
            if len(eachinterface.subkeys()) == 0:
                continue
            for eachprofile in eachinterface.subkey("Profiles").subkeys():
                profileid = [x.value() for x in list(eachprofile.values()) if x.name() == "ProfileIndex"][0]
                metadata = list(eachprofile.subkey("MetaData").values())
                for eachvalue in metadata:
                    if eachvalue.name() in ["Channel Hints", "Band Channel Hints"]:
                        channelhintraw = eachvalue.value()
                        hintlength = struct.unpack("I", channelhintraw[0:4])[0]
                        name = channelhintraw[4:hintlength + 4]
                        self.interfaces[str(profileid)] = name.decode(encoding="latin1")

    def resolve_sid(self, sid):
        return self.template_lookups.get("Known SIDS", {}).get(sid, 'unknown')

    def resolve_interface(self, interface_id):
        return self.interfaces.get(str(interface_id), "")
