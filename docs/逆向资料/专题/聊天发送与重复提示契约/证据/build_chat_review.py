# -*- coding: utf-8 -*-
"""从人工逐入口结论生成本专题清单，不修改中央台账。"""
import collections
import json
import pathlib

DIRECTORY = pathlib.Path(__file__).resolve().parent
MAIN = {
    0x64A430: ("本体清零、条件全局初始化、尾部提示调用及返回", "对象游标重置；全局100/300000门仅A67341非零时初始化", "槽文本初值及尾部提示来源对象未展开"),
    0x64A520: ("全部入口参数、门控、mode分支、原位变换、载荷构造与历史调用", "mode2仅免短门；无效收件人仍先改缓存；越界mode仍默认路由", "UI所有长度约束、网络结果及线程串行性未闭合"),
    0x64A820: ("全部单文本入口、共享门控、前缀拼接与历史调用", "先转义后过滤；共享原文缓存，消息13路由3", "前缀消费下层权限与网络结果未闭合"),
    0x64C140: ("全部逆转义、16槽比较、复制、两个游标写入", "历史键为过滤并恢复转义文本；有符号余数只在正常游标下为环形", "槽初值、合法游标保证和输入可达上限未闭合"),
    0x64C400: ("全部flag检查、计时调用、到期提示与flag清零", "长门成功后提示102并清flag；发送查询先成功会刷新last", "运行时调度先后未观察"),
    0x81BCF0: ("全部this+4写入、this返回和retn4", "仅覆盖last；不设置interval，不调用时钟", "所有调用者生命周期不在本题范围"),
    0x922930: ("全部包装函数、FILE构造、output调用、NUL尝试与原output结果返回", "count1的一位数字返回1但不NUL终止；NUL失败不覆盖原返回", "仅%d下层消费已闭合；其他格式不继承完成状态"),
    0x934100: ("全部计数模式/写入模式、cnt递减、flsbuf结果与计数写入", "字符串FILE有base时实际写入；耗尽调用flsbuf并令输出计数-1", "非字符串FILE的底层I/O不在本题完成范围"),
    0x9341D0: ("全部有符号次数循环及失败停止", "次数<=0不写；write_char失败便停止", "调用者其他格式的次数计算未展开"),
    0x934220: ("全部计数模式/源文本循环及失败停止", "base非空逐字节写；base为空的字符串FILE只加长度", "源可读范围与其他格式的宽字符转换未展开"),
}
PARTIAL = {
    0x828F60: ("仅case13前缀判定、路由0/1/2/3/4的参数读取及直接调用", "payload读+24；实际路由读+16，定向分支读+12", "其余消息、5/6分支下层与所有网络持有责任未审"),
    0x9204C0: ("strcpy入口3指令及跳到共享0x920535复制路径", "入口在9204C0，复制块属IDA的9204D0函数；无容量参数", "不把共享块归属误算为两个独立完整函数"),
    0x9204D0: ("strcat查目标NUL及与strcpy共享的复制主体", "逐字节/DWORD扫描并复制含NUL，返回原目标", "内存异常、重叠、所有调用者合法范围未闭合"),
    0x932CD0: ("flag40h字符串FILE的拒写、错误位及-1返回", "count1耗尽不写NUL，不绕过已耗尽缓冲", "文件I/O/getbuf/lseek/write后半路径未完成"),
    0x932FC0: ("%d有符号32位十进制生成、符号先写及写辅助失败传播", "一位保留，无宽度/精度时无填充；多位仅首字符，返回-1", "格式状态表全部类别、浮点、locale、宽字及非%d路径未全审"),
}
REUSE = {
    0x627160: "语言/系统单例获取，复用文本过滤与字码转换",
    0x627B60: "提示文本表单例获取，复用既有提示/字典专题",
    0x628270: "大厅对象获取，复用大厅玩家记录",
    0x628EF0: "文本转换管理器获取，复用文本过滤与字码转换",
    0x629D90: "文本表stride*id+base，不新增范围安全性结论",
    0x629E30: "读取大厅+1264自身玩家ID",
    0x64B880: "复用事件文字记录器的提示显示入口，不宣称本题完整审显示函数",
    0x64C9E0: "原位过滤文本，详细字符处理复用文本过滤与字码转换",
    0x64CDC0: "mode1百分号转01、mode0恢复，复用文本过滤与字码转换",
    0x64ED90: "语言选择，复用文本过滤与字码转换",
    0x64EFD0: "大厅+1504当前索引，复用游戏分派桥接",
    0x64F0C0: "有记录返回R+112名字，复用大厅玩家记录",
    0x64F120: "table[id]!=NULL判定，复用大厅玩家记录",
    0x64F200: "返回对象+100指针，复用商店专题，排除错误MFC名",
    0x6A2D90: "顺序找第一个同名玩家槽，复用大厅玩家记录",
    0x81BCB0: "写间隔并取tick写last，复用通知/动画专题",
    0x81BD10: "unsigned严格递增且差值达阈值，成功再次取tick写last",
}
CONTEXT = {
    0x91F6D0: "RTC栈诊断依赖；本题不审诊断正文",
    0x91F700: "RTC局部栈变量诊断依赖；本题不审诊断正文",
    0x91FB00: "strlen消费入口，仅用调用契约，不把运行库全体记为已审",
    0x922830: "strcmp消费入口，仅用调用契约，不把运行库全体记为已审",
}


def build():
    evidence = json.loads((DIRECTORY / "chat_contract_discovery.json").read_text(encoding="utf-8"))
    function_map = {int(row["va"], 16): row for row in evidence["functions"]}
    assert len(function_map) == 36
    assert set(function_map) == set(MAIN) | set(PARTIAL) | set(REUSE) | set(CONTEXT)
    rows = []
    for address, function in sorted(function_map.items()):
        if address in MAIN:
            status = "主体已审阅"
            scope, conclusion, unknown = MAIN[address]
        elif address in PARTIAL:
            status = "局部已审阅"
            scope, conclusion, unknown = PARTIAL[address]
        elif address in REUSE:
            status = "既有专题复用"
            scope, conclusion, unknown = "仅复核本题实际消费入口与E9", REUSE[address], "原专题范围以其逐函数清单为准；本题不扩大完成口径"
        else:
            status = "仅上下文导出"
            scope, conclusion, unknown = "仅保存块与指令，不升级为完成函数", CONTEXT[address], "函数完整语义未审"
        rows.append({"va": hex(address), "status": status, "scope": scope,
                     "conclusion": conclusion, "unknown": unknown,
                     "chunk_bytes": sum(row["size"] for row in function["chunks"]),
                     "evidence": ["证据/chat_contract_discovery.json"]})
    counts = dict(collections.Counter(row["status"] for row in rows))
    review = {"schema": 1, "scope": "10主体、5局部、17复用、4仅上下文；不认领完整传输层",
              "functions": rows, "counts": counts,
              "input_sha256": evidence["disk_sha256"], "idb_input_sha256": evidence["idb_input_sha256"]}
    (DIRECTORY.parent / "函数审阅清单.json").write_text(json.dumps(review, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = ["// 聊天发送与重复提示契约 / 逐函数审阅清单", "// " + "=" * 76,
             "// 36 个导出函数逐一分级：10 主体、5 局部、17 复用、4 仅上下文。",
             "// 字节数只表示导出 chunks，不表示整个调用图已审；复用不重复认领。"]
    for row in rows:
        lines += ["//", "// " + row["va"] + " / " + row["status"] + " / " + str(row["chunk_bytes"]) + " 字节",
                  "// 范围：" + row["scope"] + "。", "// 结论：" + row["conclusion"] + "。", "// 待查：" + row["unknown"] + "。"]
    (DIRECTORY.parent / "05_逐函数审阅清单.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(counts, ensure_ascii=False))


if __name__ == "__main__":
    build()
