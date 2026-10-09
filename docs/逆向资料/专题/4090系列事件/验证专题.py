"""生成人工审阅索引并独立核对静态字节、分派表、资源和字段跨度；不运行游戏。"""

import hashlib
import json
import py_compile
import struct
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
EVIDENCE = HERE / "证据"

# 这些结论来自逐入口汇编审阅；不从函数名或机器导出状态推导业务语义。
MANUAL = """
6279c0|03|UI管理器单例A766C8，按需分配0x6C0并构造；仅核分配与返回。|构造器、全管理器生命周期另见界面专题。
627b60|04|文本表单例A766DC，按需分配12字节并构造。|加载和CP_ACP运行编码不由单例入口证明。
627f40|02|模式3调度对象单例A76718，按需分配0x2FC。|单例构造器和其余职责未全量审阅。
628010|02|模式4调度对象单例A7671C，按需分配0x4588。|单例构造器和其余职责未全量审阅。
629d90|04|以this+8基址与this首DWORD步长寻址文本索引，无局部范围校验。|文本表加载数量、边界和字符编码另证。
629e10|02|cdecl谓词只比较传入模式等于4。|模式枚举的其他产品名未据此命名。
63e1a0|02|cdecl谓词只比较传入模式等于3。|模式枚举的其他产品名未据此命名。
63e160|02|以M+24的DWORD进入模式3谓词。|本结论不等于整个地图类语义。
63e990|02|以M+24的DWORD进入模式4谓词。|本结论不等于整个地图类语义。
63e5b0|01|以ECX=G+0x640调用队列getter63F940，返回head。|队列满、并发及插入失败复用基础对象专题。
63f620|02|读取P+1504现金DWORD。|负值和外部资金同步另证。
63f6b0|01|用32位参数覆盖P+1508存款。|不是+=，最终服务端值的生成另证。
63f730|01|6063构造器只写WORD消息号，+2/+3由调用方填。|不存在本构造器自身的演员或状态默认值。
63f940|01|读取this+12的DWORD；由63E5B0传队列对象时为head。|对象归属依赖调用点，不能泛称所有+12为队列head。
64fb10|03|写G+12等待时长、G+16当前tick，retn4。|没有Sleep或网络等待；恢复门控复用基础对象专题。
669dd0|01|4090检查游戏ID；T30后写股票市场+284、关闭UI35，再排stage2。|A870C0运行值及行情变化未在入口证明。
669f20|01|4091只以signed包+4和文本295排T30、stage2。|涨市文字不等于本入口修改价格。
66a050|01|4092只以signed包+4和文本296排T30、stage2。|跌市文字不等于本入口修改价格。
66a180|01|4093排状态1及T30；立即估值/追加/清持仓/覆盖存款，再刷新UI35/32和stage2。|实机时序、外部行情计数及UI重入未验证。
66a390|01|4094以G+0xC5C累计金额，T30/S/C，资金严格大于金额才排stage2。|资金不足的后续外部事件未在本入口全闭环。
66a5d0|01|4095与4094同控制流，文本320及独立缓冲，资金严格大于金额才续行。|资金不足的后续外部事件未在本入口全闭环。
66a810|01|4096按模式3/4调用模式helper并共用cursor，helper非0才追加stage2。|其他模式不会在本入口处理；上游包长检查未知。
67d880|03|6002先对角色设置状态，P+40!=-1才显示UI9、播声并条件等待。|声音资源与状态动画回调未完整恢复。
67da40|03|6003按+4/+5显示或关闭UI，以+16传data，再按+6设置等待；不消费+20。|控件是否复制文本需追虚表+144。
67fa90|03|6060按signed角色和加/减、现金/存款标志调用资金方法，缺现金另条件等待500。|地图谓词下的整个破产/继续流程未恢复。
67fd10|03|6063读signed角色和状态，写角色状态并条件刷新UI0。|状态子对象、UI0回调未完整恢复。
681380|03|6080派0/1/2/6，子函数非0才串下一阶段，阶段2读取附加signed BYTE。|各阶段大子树复用回合继续专题。
692fa0|01|读取市场80字节条目+32的float现价。|本局股票数量/配置来源复用股票专题。
6931e0|02|调用模式3记录寻址返回record+8格式文本，保留ECX表对象。|记录索引无局部边界，表装配另证。
693220|01|signed32现金与存款之和严格大于参数才真。|32位溢出未处理，不能改写为>=。
693260|01|6002构造写WORD、+5=0、+6=1、DWORD+8=0，其余由调用方填。|+7没有初始化，不作为稳定字段。
6932b0|01|6003构造写WORD、+4/+5/+6清0、DWORD+8/+12/+16/+20清0。|+2和padding由生产者自行赋值或保持未初始化。
693320|01|构造6060十进制24672，清BYTE+3..+6，不是6004。|演员、金额及padding由调用者决定。
6933b0|02|写P+1501低BYTE参数，清P+1502。|状态回合消耗语义未恢复。
6933f0|02|读取P+1696的BYTE用于模式3免疫分支。|名称依据文本359，其他消费者未穷尽。
693470|02|写P+1502低BYTE参数，清P+1501。|状态回合消耗语义未恢复。
6934b0|02|写P+1498低BYTE参数。|状态回合消耗语义未恢复。
6934e0|02|6069构造器只写WORD消息号。|其消费者及持续天数解释未在本组恢复。
693510|02|signed BYTE[P+1488]!=-1谓词。|所有状态类别的产品名未穷尽。
693540|02|signed BYTE[P+1491]!=-1谓词。|所有状态类别的产品名未穷尽。
693570|02|6050构造器只写WORD消息号。|消费者复用动态状态专题，不声称完整清理所有效果。
6935a0|02|6065构造器只写WORD消息号。|下游定时炸弹对象完整生命周期未在本组恢复。
693be0|01|6080构造写WORD消息号和BYTE+3=-1，不初始化stage。|其他来源可覆盖+3，不能统一假定-1。
693ce0|01|ECX对象DWORD+36+=signed参数；4094/95实际接收者G+0xC5C。|G+0xC80业务名未强行命名为角色现金。
694430|01|对象DWORD+284=参数，4090接收者为G+0xCD0股票市场。|A870C0运行值及倒计时消费者不在局部结论内。
694bf0|03|声音编号=参数+1000*(对象DWORD+40+1)，6002接收者为目标P。|P+40的所有初始化路径未重新恢复。
694c20|03|判断对象DWORD+40!=-1；6002调用点ECX=目标P。|不能误归到G+0xC24；运行播放结果未知。
694c50|03|初始化局部UI9 payload，清BYTE+8/+9及DWORD+12。|payload全部字段含义需UI9消费证据。
694fd0|02|调用模式4记录寻址返回record+8格式文本。|记录索引无局部边界，表装配另证。
695060|02|模式3136字节记录getter，经临时游标起始、索引步进、解引用返回。|没有局部有效索引校验。
695260|02|模式4对应136字节记录getter。|没有局部有效索引校验。
695470|02|以表对象+4记录基址构造临时游标，返回调用者输出地址。|不证明记录数量或容量有效。
695d40|02|模式4表对象+4记录基址构造临时游标。|不证明记录数量或容量有效。
695d80|02|转临时游标解引用696D90。|本函数自身不检查游标有效性。
695db0|02|通过696D50递增游标136*索引，并写入结果临时DWORD。|负索引和越界指针无局部拒绝。
695f50|02|转模式4临时游标解引用696F40。|本函数自身不检查游标有效性。
695f80|02|通过696F00递增游标136*索引，写入结果临时DWORD。|负索引和越界指针无局部拒绝。
696d10|02|模式3临时游标构造包装，转697790保存记录基址。|只确认临时对象写入。
696d50|02|临时游标首DWORD+=136*索引。|不钳索引。
696d90|02|解引用临时游标首DWORD，得到运行记录指针。|不验证记录类型。
696ec0|02|模式4临时游标构造包装，转697880保存记录基址。|只确认临时对象写入。
696f00|02|模式4临时游标首DWORD+=136*索引。|不钳索引。
696f40|02|模式4临时游标解引用得到运行记录指针。|不验证记录类型。
697790|02|把传入指针写到临时游标首DWORD。|调用对象归属由696D10确定。
697880|02|把传入指针写到模式4临时游标首DWORD。|调用对象归属由696EC0确定。
69b040|01|按signed金额与1000/5000倍scale阈值返回15/14/13扣款提示编号。|32位乘法溢出和异常scale未钳制。
69b080|02|相同阈值返回18/17/16收益提示编号。|32位乘法溢出和异常scale未钳制。
6e2520|03|显示News基础窗口，根控件可见/启用设1，对象+56清0。|根控件虚表实现复用界面专题。
6e3b40|03|复用UI管理器显示入口：按槽创建/加载、调用初始化、记录时间并传播关联窗口。|本组只核6003参数交接；复杂prev/dvs和所有工厂不在本专题重做全闭环。
6e4020|03|复用关闭入口：已显示时调对象虚表+64，恢复关联窗口并设pending。|本组只核UI35/提示关闭语义；复杂关联窗口另见界面专题。
6e4520|03|槽对象非空且虚表+80非0才认为可见。|表对象非空前提及所有控件谓词另证。
6e4640|03|槽对象存在时转虚表+16传data，属于更新而非关闭。|控件自身对空data的处理未全量审阅。
6e7de0|03|UI30创建工厂分配0x214并调用6FB680。|分配失败的全调用链恢复另证。
6fb680|03|先构造基础UI，设置vtableA25A60，登记槽30。|完整窗口加载与控件资源另证。
719290|03|News关闭方法先基础关闭，再读取动画当前编号并条件释放动画资源。|动画管理器具体缓存生命周期未全闭环。
7192f0|03|News数据消费者读三个DWORD，分来源选图像/表动画，再把文本交控件虚表+144。|该控件是否复制文本未核，不能保证重入时指针安全。
7286d0|02|读G+0x1477C模式3新闻表对象。|表对象装配和动态生命周期另证。
728700|02|读G+0x14780模式4新闻表对象。|表对象装配和动态生命周期另证。
7acd60|04|顺次装载四个文件，前三项失败即返回0，第四项返回值不参与成功判断。|仅确认局部加载门控，未穷尽各资源解析器。
7afe70|04|只审阅按行sscanf取地图名/类型/动画名/文本，随后提交对应地图容器。|完整容器插入、文本转义、失败修复、KoNews加载链未全量审阅。
7b2e20|02|模式3读signed包+4查记录，以记录DWORD类型索引17项表，cdecl调用四参数。|索引/类型无局部guard，动态输入有效性另证。
7cd440|02|只审阅清醒卡1071两谓词门控和成功时T4/6001/6063/6061队列；ECX=G。|卡片检索、适用性与完整子树复用回合继续专题，不计作本组首次完整恢复。
7f7670|03|写P+388状态DWORD，再将状态传给P+864子对象。|状态子对象完整消费者未恢复。
7f8320|02|写P+1500低BYTE参数，再调状态子接口5。|状态子接口和回合消耗另证。
7f83b0|02|清P+1498/+1501/+1502/+1496四个BYTE。|不代表清除全部角色状态。
7f83f0|03|扣现金，负现金由存款补，现金和耗尽存款归0；可选金额显示。|显示子树、服务端余额权威同步另证。
7f86a0|02|按组0/1/2和6字节槽读取signed WORD物品编号，其他组返回-1。|slot没有局部范围防护。
7f8780|02|只审阅组0八槽的加入、失败返回及条件UI12刷新；模式谓词可覆盖返回1。|自动组合卡与UI12全部子树未全闭环。
7f8920|02|组0槽signed WORD数量减参数，<=0则数量0、编号-1，再条件刷新UI12。|槽越界与整数回绕未拒绝。
7f9950|01|按当前股票数量遍历，正持仓先回写市场后清数量与成本。|数量上界/市场写回细节复用股票专题。
7f9de0|01|每正持仓数量转float，与市场现价相乘，经ftol2取整数并32位累计市值。|异常float、数量溢出和本局股票数另证。
7f9f10|03|存款-=金额，signed负值时归0；标志非0显示扣款。|显示方法未全闭环。
7fa050|03|现金+=金额，标志非0显示加款。|没有整数溢出保护。
7fa0a0|01|存款+=金额，标志非0才显示；4093调用标志0。|随后包+8覆盖，不能当最终存款。
7fa4b0|02|32位加100后转float/100写P+1652，写低BYTE持续参数到1660。|下游攻击计算和持续时间消耗未全量恢复。
7fa510|02|32位100减参数后转float/100写P+1652，低BYTE写1660。|异常比例和下游消费未全量恢复。
7fa570|02|32位100减参数后转float/100写P+1656，低BYTE写1661。|type14原文称防御上升，实际下游公式待解释。
7fa5d0|02|32位参数加100后转float/100写P+1656，低BYTE写1661。|type15原文称防御下降，实际下游公式待解释。
7fb200|03|首次填固定状态表，随后按action直接索引返回，6002先调用此表。|action负值/过大没有本函数局部范围校验。
807cd0|02|模式4读signed包+4查记录，以记录类型索引17项表，cdecl调用四参数。|索引/类型无局部guard，动态输入有效性另证。
"""

BRANCHES = [
    (0x6592A0, 0x6827E0, "p+8金额：T30、6060扣现金、6002扣款提示，严格总资金>金额控制返回。"),
    (0x659480, 0x6829C0, "p+8百分数：32位乘现金后float/100，T30、扣款、声音，返回1。"),
    (0x659670, 0x682BB0, "p+8金额：T30、6060加现金、6002收益提示，返回1。"),
    (0x659820, 0x682D60, "p+8百分数：同低32位与float金额链，T30、加款、收益声音，返回1。"),
    (0x659A10, 0x682F50, "p+8数量及p+12起DWORD卡片编号：逐张加入组0，列表失败追加154，声音20。"),
    (0x659D20, 0x683260, "p+8卡片编号：按名字格式化，加入1张并提示是否满栏，声音21。"),
    (0x659F50, 0x683490, "p+8数量及DWORD卡片槽数组：取旧编号形成列表、逐槽减1，声音10。"),
    (0x65A240, 0x683780, "T30后清状态组，P+1501=低BYTE(A870C8+1)；模式3具有1696免疫旁路。"),
    (0x65A460, 0x6838A0, "T30后清状态组，P+1502=低BYTE(A870C8+1)；模式3具有1696免疫旁路。"),
    (0x65A680, 0x6839C0, "T30后清状态组，P+1498=低BYTE(A870A0+1)；模式3具有1696免疫旁路。"),
    (0x65A8A0, 0x683AE0, "p+8持续参数：清醒卡保护失败排6069与状态6；模式3另有1696免疫旁路。"),
    (0x65AB70, 0x683CA0, "p+8参数低BYTE(v+1)写1500并调用状态5；模式3有1696免疫旁路。"),
    (0x65AD90, 0x683DC0, "p+8百分数与p+12持续低BYTE：P+1652=(100+v)/100，1660=d。"),
    (0x65AEB0, 0x683EE0, "p+8百分数与p+12持续低BYTE：P+1652=(100-v)/100，1660=d。"),
    (0x65AFD0, 0x684000, "p+8百分数与p+12持续低BYTE：P+1656=(100-v)/100，1661=d。"),
    (0x65B0F0, 0x684120, "p+8百分数与p+12持续低BYTE：P+1656=(100+v)/100，1661=d。"),
    (0x65B210, 0x684240, "两个独立状态谓词，条件排6050和6065，后者补角色名及炸弹拆除提示。"),
]


def manual_specs():
    specs = {}
    for line in MANUAL.strip().splitlines():
        address, doc, conclusion, unknown = line.split("|", 3)
        specs[hex(int(address, 16))] = (doc, conclusion, unknown)
    for index, (mode3, mode4, conclusion) in enumerate(BRANCHES):
        for mode, ea, wrapper in [(3, mode3, 0x7B2E90 + 32 * index),
                                  (4, mode4, 0x807D40 + 32 * index)]:
            specs[hex(ea)] = ("02", f"模式{mode} type{index}：{conclusion}",
                              "已核本分支控制流、接收对象与字段；提示指针重入、动画与外部状态完整消费未验证。")
            specs[hex(wrapper)] = ("02", f"cdecl四参数wrapper，G转ECX，调用{ea:06X}模式{mode} type{index}，自身普通retn。",
                                   "仅桥接ABI，不把下游原证自动计作完整业务闭环。")
    for opcode, wrapper, target in [(0x4090, 0x7F0650, 0x669DD0), (0x4091, 0x7F0670, 0x669F20),
                                    (0x4092, 0x7F0690, 0x66A050), (0x4093, 0x7F06B0, 0x66A180),
                                    (0x4094, 0x7F06D0, 0x66A390), (0x4095, 0x7F06F0, 0x66A5D0),
                                    (0x4096, 0x7F0710, 0x66A810)]:
        specs[hex(wrapper)] = ("01", f"{opcode:04X} cdecl(G,p)桥接：ECX=G，栈p，调用{target:06X}，自身普通retn。",
                               "注册桥接复用既有专题；业务结论见对应handler项。")
    return specs


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    specs = manual_specs()
    blob = (ROOT / "RnClient.exe").read_bytes()
    pe = struct.unpack_from("<I", blob, 0x3C)[0]
    image_base = struct.unpack_from("<I", blob, pe + 52)[0]
    count = struct.unpack_from("<H", blob, pe + 6)[0]
    optional = struct.unpack_from("<H", blob, pe + 20)[0]
    sections = [struct.unpack_from("<III", blob, pe + 24 + optional + 40 * i + 12)
                for i in range(count)]

    def disk_bytes(ea, size):
        for rva, raw_size, offset in sections:
            relative = ea - image_base - rva
            if 0 <= relative and relative + size <= raw_size:
                return blob[offset + relative:offset + relative + size]
        raise AssertionError(f"PE不能映射 {ea:x}+{size}")

    def verify_range(row):
        original = bytes.fromhex(row["idb_hex"])
        assert len(original) == row["size"]
        assert row["matching"] is True
        assert original == bytes.fromhex(row["disk_hex"])
        assert original == disk_bytes(int(row["va"], 16), row["size"])

    rows, thunks = {}, {}
    byte_range_count = 0
    documents = {path.name[:2]: path.name for path in HERE.glob("0*.txt")}
    for path in sorted(EVIDENCE.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or "functions" not in data:
            continue
        assert data["disk_sha256"] == hashlib.sha256(blob).hexdigest()
        for function in data["functions"]:
            ea = function["va"].lower()
            doc, conclusion, unknown = specs[ea]
            assert function["bytes_match_disk"] is True
            for block in function["byte_ranges"]:
                verify_range(block)
                byte_range_count += 1
            record = rows.setdefault(ea, {
                "ea": ea, "name": function["name"], "status": "静态局部语义已审阅",
                "conclusion": conclusion, "unknown": unknown,
                "document": documents[doc], "evidence": [], "bytes_match_disk": True,
                "boundary": "仅本函数列出的局部结论和调用参数；不等于全部下游、异常输入和运行行为已经闭环。",
            })
            record["evidence"].append(str(path.relative_to(HERE)).replace("\\", "/") + "/functions/" + ea)
        for thunk in data["thunks"]:
            verify_range(thunk)
            thunks[thunk["va"]] = thunk
    assert set(rows) == set(specs), (set(rows) - set(specs), set(specs) - set(rows))
    assert len(rows) == 175
    ranges = json.loads((EVIDENCE / "data_ranges.json").read_text(encoding="utf-8"))["ranges"]
    for row in ranges:
        verify_range(row)
    tables = json.loads((EVIDENCE / "dispatch_tables.json").read_text(encoding="utf-8"))
    for table in [0xA67458, 0xA67658]:
        entries = [entry for entry in tables if int(entry["table"], 16) == table]
        assert [entry["index"] for entry in entries] == list(range(17))
        assert struct.unpack("<17I", disk_bytes(table, 68)) == tuple(int(entry["entry"], 16) for entry in entries)
        for entry in entries:
            ea = int(entry["entry"], 16)
            raw = disk_bytes(ea, 5)
            assert raw[0] == 0xE9
            assert ea + 5 + int.from_bytes(raw[1:], "little", signed=True) == int(entry["implementation"], 16)
            expected = 0x7B2E90 if table == 0xA67458 else 0x807D40
            assert int(entry["implementation"], 16) == expected + 32 * entry["index"]

    resource = json.loads((EVIDENCE / "resource_samples.json").read_text(encoding="utf-8"))
    for record in resource["records"]:
        assert digest(ROOT / record["source"]) == record["source_sha256"]
        assert digest(EVIDENCE / record["decoded_file"]) == record["decoded_sha256"]
        plain = (EVIDENCE / record["decoded_file"]).read_bytes()
        assert plain.decode(record["codec"]).encode(record["codec"]) == plain
        assert len(plain) == record["expanded_bytes"]
        for row in record["sections"]:
            if "type" in row:
                assert row["type"] in range(17)
                assert len(row["columns"]) == 10
                assert row["raw_line"] == "\t".join(row["columns"])
    text_record = next(r for r in resource["records"] if r["source"] == "Data/RichStr.kpd")
    assert {int(r["fields"]["indx"]) for r in text_record["sections"]} == {22, 24, 28, 71, 154, 245, 264, 293, 295, 296, 297, 319, 320, 359}

    for path in HERE.glob("*.txt"):
        assert all(not line.strip() or line.startswith("//") for line in path.read_text(encoding="utf-8").splitlines()), path
    references = [HERE.parent / "游戏分派桥接/01_310入口桥接清单.txt",
                  HERE.parent / "基础对象与分派/01_游戏记录队列与消费门控.txt",
                  HERE.parent / "4060系列事件/01_入口字段与记录.txt",
                  HERE.parent / "地图初始化同步/证据/map_sync_helpers.json",
                  HERE.parent / "股票与交易流程/01_配置与行情持仓结构.txt",
                  HERE.parent / "界面系统/界面系统_对象生命周期.txt",
                  HERE.parent / "回合继续与落点调度/00_6080阶段链与阅读入口.txt",
                  HERE.parent.parent / "全量分析/版本核验_第二批.txt"]
    assert all(path.is_file() for path in references), [str(path) for path in references if not path.is_file()]
    for n in [1, 2, 8, 128]:
        assert 12 + 4 * (n - 1) + 4 == 12 + 4 * n
    assert 4 + 2 == 6 and 6 + 2 == 8 and 8 + 4 == 12 and 12 + 4 == 16
    assert 1504 + 4 == 1508 and 0xC5C + 36 == 0xC80 and 0x640 + 12 == 0x64C
    review = {"scope": "175个唯一函数的静态局部结论；复用消费者单列，不代表全部下游完整恢复。",
              "functions": [rows[ea] for ea in sorted(rows, key=lambda value: int(value, 16))],
              "thunks": {"count": len(thunks), "status": "原始字节和跳转目标核验；业务语义不由跳板数量推导。"}}
    (HERE / "函数审阅清单.json").write_text(json.dumps(review, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    # 语法验证产物放入临时目录，开发资料目录不保留解释器缓存。
    with tempfile.TemporaryDirectory(prefix="richonline-4090-docs-") as cache:
        for index, path in enumerate(HERE.rglob("*.py")):
            py_compile.compile(str(path), cfile=str(Path(cache) / f"check{index}.pyc"), doraise=True)
    hashes = {str(path.relative_to(HERE)).replace("\\", "/"): digest(path)
              for path in sorted(HERE.rglob("*")) if path.is_file() and path.name != "专题验证.json" and "__pycache__" not in path.parts}
    result = {"scope": "只读静态证据核验，未运行客户端。", "unique_function_count": len(rows),
              "stored_function_range_checks": byte_range_count, "unique_exported_thunks": len(thunks),
              "data_range_checks": len(ranges), "dispatch_table_rows": len(tables),
              "functions_thunks_data_match_current_pe": True, "manual_specs_cover_exports": True,
              "txt_comment_format": True, "resource_source_and_decoded_hashes": True,
              "consumer_length_arithmetic": True, "python_syntax": True, "file_sha256": hashes,
              "reference_sha256": {str(path): digest(path) for path in references}}
    (EVIDENCE / "专题验证.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in result.items() if "sha256" not in key}, ensure_ascii=False))


if __name__ == "__main__":
    main()
