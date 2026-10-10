# -*- coding: utf-8 -*-
"""生成经作者逐指令检查的局部调用表与分级；只写本专题。"""
import collections
import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
NAMES = {0x8E67C0: "公共控件", 0x8F1000: "scrollbar", 0x8F9490: "listbox",
         0x901F30: "progress", 0x905420: "slider", 0x909330: "tree",
         0x90AAA0: "checkbox", 0x90E060: "label"}
OFFSETS = {
    0x8E67C0: [56, 72, 60, 76, 64, 80, 68, 84, 196, 236, 276, 316],
    0x8F1000: [608, 648, 688, 728, 784, 824, 864, 904, 960, 1000, 1040, 1080],
    0x8F9490: [628, 668, 708, 748], 0x901F30: [608],
    0x905420: [608, 648, 688, 728], 0x909330: [848, 856, 860],
    0x90AAA0: [596], 0x90E060: [148, 152, 156, 160, 132, 136, 140, 144],
}
KEYS = {
    0x8E67C0: ["HintNormalBColor", "HintNormalFColor", "HintMouseInBColor", "HintMouseInFColor",
                "HintMouseDownBColor", "HintMouseDownFColor", "HintDisableBColor", "HintDisableFColor",
                "NormalBColor", "MouseInBColor", "MouseDownBColor", "DisableBColor"],
    0x8F1000: ["Btn" + str(i) + state + "BColor" for i in range(3)
               for state in ["Normal", "MouseIn", "MouseDown", "Disable"]],
    0x8F9490: ["NorBColor", "InBColor", "DownBColor", "DisBColor"],
    0x901F30: ["TopColor"],
    0x905420: ["NormalBtnBColor", "MouseInBtnBColor", "MouseDownBtnBColor", "DisableBtnBColor"],
    0x909330: ["LineColor", "PlusColor", "PlusBColor"],
    0x90AAA0: ["CheckColor"],
    0x90E060: [state + "CapFont" + layer + "Color" for layer in ["F", "B"]
               for state in ["Normal", "MouseIn", "MouseDown", "Disable"]],
}


def build():
    raw = json.loads((HERE / "hex_raw.json").read_text(encoding="utf-8"))
    strings = {int(x["va"], 16): bytes.fromhex(x["ida_hex"]) for x in raw["strings"]}
    calls, functions = [], []
    for f in raw["functions"]:
        ea = int(f["va"], 16)
        if ea in NAMES:
            sites = {x["site"] for x in f["calls"] if x["resolved"] == "0x8e0380"}
            rows = f["instructions"]
            found = []
            for i, insn in enumerate(rows):
                if insn["va"] not in sites:
                    continue
                window = rows[max(0, i-8):i+9]
                key_instruction = next(x for x in rows[i+1:i+7]
                                       if bytes.fromhex(x["hex"])[0] == 0x68)
                key_va = int.from_bytes(bytes.fromhex(key_instruction["hex"])[1:], "little")
                key = strings[key_va].split(b"\0")[0].decode("ascii")
                callback = next(x for x in rows[i+1:i+8] if x["text"].startswith("call"))
                found.append(key)
                calls.append({"owner": f["va"], "control": NAMES[ea], "call": insn["va"],
                              "offset": OFFSETS[ea][len(found)-1], "key": key,
                              "key_va": hex(key_va), "key_push": key_instruction["va"],
                              "consumer_call": callback["va"], "callback_slot": 96,
                              "evidence_window": [x["va"] for x in window]})
            assert found == KEYS[ea]
            scope = "仅" + str(len(found)) + "个颜色字段读取、格式化返回指针交接和+96间接回调"
            conclusion = NAMES[ea] + "字段与键已逐项对应；回调前未显式复制结果"
            unknown = "完整保存函数、回调绑定/深拷贝/文件格式/其他属性未闭合"
            status = "局部已审阅"
        else:
            status = "主体已审阅"
            scope, conclusion, unknown = {
                0x8E0380: ("全部模板拷贝、临时区清零、ltoa调用、三次长度读取、右对齐拷贝和返回",
                           "常规串行条件下输出0x加8位小写hex；结果指针共用且下一次调用覆盖",
                           "线程串行、重入约束和全局源代码容量未证明"),
                0x92BBD0: ("全部radix10负号判断、参数交接、Buffer返回",
                           "radix16不会写负号；Value高位不触发取负",
                           "所有调用者合法radix及目标区容量不在本题范围"),
                0x92BAD0: ("全部可选符号、unsigned除法/余数、字符输出、NUL和首尾反转",
                           "无缓冲容量或radix校验；基数16最大8位，0仍输出一位",
                           "一般调用以有效缓冲和radix2..36为契约；非法参数无兼容保证"),
            }[ea]
        functions.append({"va": f["va"], "status": status, "scope": scope, "conclusion": conclusion,
                          "unknown": unknown, "chunk_bytes": sum(x["size"] for x in f["chunks"]),
                          "evidence": ["证据/hex_raw.json"]})
    review = {"schema": 1, "counts": dict(collections.Counter(x["status"] for x in functions)),
              "functions": functions, "reuse": [{"va": "0x8e0450", "status": "既有专题复用",
              "scope": "仅规范0x八位输入的有限数值反解析", "path": "../界面数值与颜色解析契约/函数审阅清单.json"}]}
    (HERE.parent / "函数审阅清单.json").write_text(json.dumps(review, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    (HERE / "save_color_calls.json").write_text(json.dumps(calls, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    lines = ["// 十六进制文本格式化 / 逐函数审阅清单", "// " + "=" * 76,
             "// 11个导出函数：3个主体、8个调用方局部；另复用8E0450，不重复认领。"]
    for row in functions:
        lines += ["//", "// " + row["va"] + " / " + row["status"], "// 范围："+row["scope"]+"。",
                  "// 结论："+row["conclusion"]+"。", "// 待查："+row["unknown"]+"。"]
    (HERE.parent / "05_逐函数审阅清单.txt").write_text("\n".join(lines)+"\n", encoding="utf-8")
    lines = ["// 十六进制文本格式化 / 45个保存调用点", "// " + "=" * 76,
             "// 偏移为当前控件对象的字节偏移；消费者均为管理器+96处的间接回调。",
             "// 局部参数交接不等于文件已写入，也不证明回调会深拷贝字符串。"]
    for row in calls:
        lines += ["//", "// "+row["owner"]+" / "+row["control"]+" / call "+row["call"],
                  "// 对象+"+str(row["offset"])+" -> "+row["key"]+"；消费call "+row["consumer_call"]+"。"]
    (HERE.parent / "04_保存字段逐项清单.txt").write_text("\n".join(lines)+"\n", encoding="utf-8")
    print(json.dumps({"functions": review["counts"], "save_calls": len(calls)}, ensure_ascii=False))


if __name__ == "__main__":
    build()
