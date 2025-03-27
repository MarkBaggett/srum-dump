import win32com.client


def create_shadow_copy(volume_path):
    try:
        wmi_service = win32com.client.GetObject("winmgmts:\\\\.\\root\\cimv2")
        shadow_copy_class = wmi_service.Get("Win32_ShadowCopy")
        in_params = shadow_copy_class.Methods_("Create").InParameters.SpawnInstance_()
        in_params.Volume = volume_path
        in_params.Context = "ClientAccessible"
        out_params = wmi_service.ExecMethod("Win32_ShadowCopy", "Create", in_params)
        if out_params.ReturnValue == 0:
            return out_params.ShadowID
        else:
            return out_params.ReturnValue
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

volume_to_shadow = "C:\\" #Try C:\
shadow_id = create_shadow_copy(volume_to_shadow)

if shadow_id is not None:
    if shadow_id == 0:
        print("Shadow copy created")
    else:
        print(f"return value: {shadow_id}")