"""在已加载提取RTC.py的IDA只读环境中执行；不修改数据库。"""
import json

import ida_nalt
import ida_xref

# 三处汇编均以未减偏移的参数作为索引，边界分别为103、50、109。
# 对压缩表，IDA的lowcase与values共用联合字段，不能把前者当索引基数。
ranges, switches = [], []
for site in [0x828FB6, 0x82B0CA, 0x6BE354]:
    info = ida_nalt.get_switch_info(site)
    cases = ida_xref.calc_switch_cases(site, info)
    ranges.append(raw(info.jumps, info.get_jtable_size()*info.get_jtable_element_size(), "switch_jumps"))
    if info.values:
        ranges.append(raw(info.values, info.ncases*info.get_vtable_element_size(), "switch_values"))
    switches.append({"site": hex(site), "jumps": hex(info.jumps), "values": hex(info.values),
                     "index_base": 0, "ncases": info.ncases,
                     "jump_count": info.get_jtable_size(), "jump_size": info.get_jtable_element_size(),
                     "value_size": info.get_vtable_element_size(),
                     "cases": [{"values": list(values), "target": hex(target)}
                               for values, target in zip(cases.cases, cases.targets)]})
(HERE / "data_ranges.json").write_text(json.dumps(
    {"disk_sha256": fingerprint, "ranges": ranges, "switches": switches},
    ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
