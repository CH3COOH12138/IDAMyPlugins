import ida_bytes
import idaapi
import idc

class HexFillerForm(idaapi.Form):
    def __init__(self):
        self.fill_bytes = b""
        # 默认起始地址使用当前光标所在地址
        self.start_address = idaapi.get_screen_ea()

        idaapi.Form.__init__(self,
r"""Hex Filler
{FormChangeCb}
<Start address:{start_addr}>
<Hex pattern  :{hex_pattern}>

""",
            {
                'start_addr': idaapi.Form.NumericInput(value=self.start_address, swidth=16, tp=idaapi.Form.FT_ADDR),
                'hex_pattern': idaapi.Form.StringInput(value="", tp=idaapi.Form.FT_ASCII, width=512),
                'FormChangeCb': idaapi.Form.FormChangeCb(self.OnFormChange)
            }
        )

    def _validate_inputs(self):
        # 获取用户输入并做基本校验
        start_addr = self.GetControlValue(self.start_addr)
        hex_str = self.GetControlValue(self.hex_pattern).strip().replace(" ", "")
        if start_addr is None:
            idaapi.warning("Please enter a valid start address!")
            return 0
        if not hex_str:
            idaapi.warning("Hex pattern cannot be empty!")
            return 0
        try:
            self.fill_bytes = bytes.fromhex(hex_str)
        except ValueError as e:
            idaapi.warning(f"Invalid hex format: {e}")
            return 0

        return 1

    def OnFormChange(self, fid):
        # 当用户点击 OK（fid==-2）时调用输入验证
        if fid == -2:
            return self._validate_inputs()
        return 1

class HexFillerPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Auto fill segment with specified hex pattern"
    wanted_name = "Hex Filler"
    wanted_hotkey = "Ctrl-Shift-F"
    help = "Fill entire segment starting from given address with the hex pattern"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        form = HexFillerForm()
        form.Compile()
        ok = form.Execute() 
        if ok == 1:
            self._perform_filling(form)
        form.Free()

    def _perform_filling(self, form):
        start_addr = form.start_address
        fill_data = form.fill_bytes
        pattern_len = len(fill_data)

        try:
            ida_bytes.patch_bytes(start_addr, fill_data)
        except Exception as e:
            idaapi.warning(str(e))
            return

        print(f"Successfully filled {pattern_len} bytes from {start_addr:#x} to {(start_addr + pattern_len):#x}.")

def PLUGIN_ENTRY():
    return HexFillerPlugin()
