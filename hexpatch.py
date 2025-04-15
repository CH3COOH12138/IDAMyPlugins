import ida_bytes
import idaapi

class HexPatcherForm(idaapi.Form):
    def __init__(self):
        # 初始化成员变量
        self.original_bytes = b""
        self.new_bytes = b""
        
        # 设置默认地址范围
        self.start_address = idaapi.get_screen_ea()
        self.end_address = self.start_address + 0x10

        self.options = 0

        idaapi.Form.__init__(
            self,
            r"""Hex Pattern Patcher
{FormChangeCb}
<Start address :{start_addr}>
<End address   :{end_addr}>
<Original bytes:{original_pattern}>
<New bytes     :{new_pattern}>
<Options       :{search_options}>

""",
            {
                'original_pattern': idaapi.Form.StringInput(value="", tp=idaapi.Form.FT_ASCII, width=40),
                'new_pattern': idaapi.Form.StringInput(value="", tp=idaapi.Form.FT_ASCII, width=40),
                'start_addr': idaapi.Form.NumericInput(value=self.start_address, swidth=16, tp=idaapi.Form.FT_ADDR),
                'end_addr': idaapi.Form.NumericInput(value=self.end_address, swidth=16, tp=idaapi.Form.FT_ADDR),
                'search_options': idaapi.Form.DropdownListControl(
                    items=["All occurrences", "First occurrence"],
                    readonly=True,
                    selval=0
                ),
                'FormChangeCb': idaapi.Form.FormChangeCb(self.OnFormChange)
            }
        )

    def OnFormChange(self, fid):
        # 当按下 OK 时（fid == -2）进行输入验证
        if fid == -2:
            return self._validate_inputs()
        return 1

    def _validate_inputs(self):
        try:
            self.options = self.GetControlValue(self.search_options)
            # 获取并处理输入
            orig_str = self.GetControlValue(self.original_pattern).strip().replace(" ", "")
            new_str = self.GetControlValue(self.new_pattern).strip().replace(" ", "")
            
            if not orig_str or not new_str:
                idaapi.warning("Input cannot be empty!")
                return 0
                
            # 转换为 bytes
            self.original_bytes = bytes.fromhex(orig_str)
            self.new_bytes = bytes.fromhex(new_str)
            
            # 验证两者长度是否一致
            if len(self.original_bytes) != len(self.new_bytes):
                idaapi.warning("Pattern lengths must match!")
                return 0
                
            # 验证地址范围
            self.start_address = self.GetControlValue(self.start_addr)
            self.end_address = self.GetControlValue(self.end_addr)
            if self.start_address >= self.end_address:
                idaapi.warning("End address must be greater than start address!")
                return 0
        except ValueError as e:
            idaapi.warning(f"Invalid hex format: {str(e)}")
            return 0
            
        return 1

class HexPatcherPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Advanced Hex Pattern Patcher"
    wanted_name = "Hex Pattern Patcher"
    wanted_hotkey = "Ctrl-Shift-H"
    help = "Batch hex pattern replacement tool"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        form = HexPatcherForm()
        form.Compile()
        ok = form.Execute()
        if ok == 1:
            self._perform_patching(form)
        form.Free()

    def _perform_patching(self, form):
        start_addr = form.start_address
        end_addr = form.end_address
        original = form.original_bytes
        new_pat = form.new_bytes
        pattern_len = len(original)
        first_only = form.options == 1

        patched_count = 0
        ea = start_addr
        while ea < end_addr - pattern_len + 1:
            try:
                current = ida_bytes.get_bytes(ea, pattern_len)
                if current == original:
                    ida_bytes.patch_bytes(ea, new_pat)
                    patched_count += 1
                    if first_only:
                        break
                    ea += pattern_len
                else:
                    ea += 1
            except Exception as e:
                idaapi.warning(str(e))
                ea += 1
                continue

        print(f"Successfully patched {patched_count} locations.")

def PLUGIN_ENTRY():
    return HexPatcherPlugin()
