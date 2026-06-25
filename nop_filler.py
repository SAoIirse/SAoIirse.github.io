import ida_kernwin
import ida_bytes
import idc
import idaapi



class NopFiller(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "花指令清理工具 - NOP填充"
    help = "将选中的机器码替换为0x90(NOP)"
    wanted_name = "NopFiller"
    wanted_hotkey = "Alt-N"

    def init(self):
        print("=" * 60)
        print("NOP填充插件已加载 - 使用 Alt+N 或右键菜单运行")
        print("功能：将选中区域的机器码替换为0x90")
        print("=" * 60)
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        fill_selected_with_nop()

    def term(self):
        pass


def fill_selected_with_nop():
    """
    将选中区域的字节替换为0x90(NOP)
    """
    # 方法1: 使用 idc.read_selection() - 最直接的方法
    start_ea = idc.read_selection_start()
    end_ea = idc.read_selection_end()

    # 如果上面的方法失败，尝试使用 idaapi.get_highlighted_range
    if start_ea == idc.BADADDR or end_ea == idc.BADADDR:
        try:
            if hasattr(idaapi, 'get_highlighted_range'):
                start_ea, end_ea = idaapi.get_highlighted_range()
        except:
            pass

    # 如果还是没有选中区域，尝试获取当前地址并填充一个字节
    if start_ea == idc.BADADDR or end_ea == idc.BADADDR:
        # 获取当前光标位置的地址
        current_ea = idc.get_screen_ea()
        if current_ea != idc.BADADDR:
            # 询问是否填充当前地址的一个字节
            question = f"未选中区域，是否要填充当前地址 {hex(current_ea)} 的一个字节为NOP？"
            if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, question) == ida_kernwin.ASKBTN_YES:
                start_ea = current_ea
                end_ea = current_ea + 1
            else:
                # 尝试获取当前函数
                func_start = idc.get_func_attr(current_ea, idc.FUNCATTR_START)
                func_end = idc.get_func_attr(current_ea, idc.FUNCATTR_END)

                if func_start != idc.BADADDR and func_end != idc.BADADDR:
                    question = f"是否要填充当前函数 {hex(func_start)}-{hex(func_end)} 的全部内容？"
                    if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, question) == ida_kernwin.ASKBTN_YES:
                        start_ea = func_start
                        end_ea = func_end
                    else:
                        ida_kernwin.warning("请先选择要填充的区域（用鼠标拖选或Shift+方向键）")
                        return
                else:
                    ida_kernwin.warning("请先选择要填充的区域（用鼠标拖选或Shift+方向键）")
                    return
        else:
            ida_kernwin.warning("请先选择要填充的区域（用鼠标拖选或Shift+方向键）")
            return

    # 确保地址有效
    if start_ea == idc.BADADDR or end_ea == idc.BADADDR or start_ea >= end_ea:
        ida_kernwin.warning("无效的地址范围，请重新选择")
        return

    # 计算要填充的字节数
    nop_count = end_ea - start_ea

    # 确认对话框
    question = f"确定要将 {hex(start_ea)} 到 {hex(end_ea - 1)} 的 {nop_count} 个字节替换为NOP(0x90)吗？"

    if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, question) != ida_kernwin.ASKBTN_YES:
        print("操作已取消")
        return

    # 保存原始字节（用于日志）
    original_bytes = []
    print(f"正在填充NOP: {hex(start_ea)} - {hex(end_ea - 1)} ({nop_count} 字节)")

    # 执行填充
    bytes_filled = 0
    for ea in range(start_ea, end_ea):
        # 保存原始字节
        if bytes_filled < 10:  # 只保存前10个字节用于日志
            original_bytes.append(ida_bytes.get_byte(ea))

        # 填充NOP
        ida_bytes.patch_byte(ea, 0x90)
        bytes_filled += 1

        # 每填充100字节显示进度
        if bytes_filled % 100 == 0 and bytes_filled > 0:
            print(f"  进度: {bytes_filled}/{nop_count}")

    # 刷新显示
    try:
        ida_bytes.refresh_idaview_anyway()
    except:
        try:
            idaapi.refresh_idaview()
        except:
            pass

    print(f"✓ 成功填充 {bytes_filled} 个NOP指令")

    # 显示原始字节信息
    if original_bytes:
        log_msg = f"原始字节（前{len(original_bytes)}个）: "
        for b in original_bytes:
            log_msg += f"{hex(b)} "
        print(log_msg)

    # 显示完成消息
    ida_kernwin.info(f"已成功将 {bytes_filled} 字节替换为NOP")


class NopFillerPopup(ida_kernwin.action_handler_t):
    """
    右键菜单处理器
    """

    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        fill_selected_with_nop()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


def register_popup_menu():
    """
    注册右键菜单项
    """
    try:
        # 创建动作描述符
        action_desc = ida_kernwin.action_desc_t(
            "nop_filler:fill_selected",
            "填充选中区域为NOP",
            NopFillerPopup(),
            "Alt+N",
            "将选中区域的机器码替换为0x90(NOP)",
            199
        )

        # 注册动作
        ida_kernwin.register_action(action_desc)

        # 添加到编辑菜单
        ida_kernwin.attach_action_to_menu(
            "Edit/",
            "nop_filler:fill_selected",
            ida_kernwin.SETMENU_APP
        )

        print("菜单已注册: 编辑菜单 -> 填充选中区域为NOP")

    except Exception as e:
        print(f"注册菜单时出错: {e}")


# 主要执行函数
def main():
    fill_selected_with_nop()


# 插件入口
if __name__ == "__main__":
    main()
else:
    def PLUGIN_ENTRY():
        register_popup_menu()
        return NopFiller()
