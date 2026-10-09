"""生成 40EE..40FE、4200..4214、5000 事件的中文审阅清单。"""
from pathlib import Path
import json, re

ROOT = Path(__file__).resolve().parents[4]
EVIDENCE = Path(__file__).parent / "证据"

def main():
    mapping = json.loads((ROOT / "docs/逆向资料/专题/游戏分派桥接/证据/dispatch_bridges_raw.json").read_text(encoding="utf-8"))
    exported = json.loads((EVIDENCE / "handlers.json").read_text(encoding="utf-8"))
    by_va = {f["va"]: f for f in exported["functions"]}
    selected = []
    for e in mapping["entries"]:
        code = int(e["code"], 16)
        if not (0x40EE <= code <= 0x40FE or 0x4200 <= code <= 0x4214 or code == 0x5000):
            continue
        impl = hex(int(e["resolved_calls"][0]["implementation"], 16))
        f = by_va.get(impl, {})
        pseudo = "\n".join(f.get("pseudocode", []))
        strings = sorted(set(re.findall(r"(?:sub_60FC52|sub_6092DA)\(a1: ([0-9]+)", pseudo)))
        sizes = sorted({int(value, 0) for value in re.findall(r"Size: (0x[0-9A-Fa-f]+|[0-9]+)u?", pseudo)})
        selected.append({
            "事件": e["code"], "桥接入口": e.get("bridge"), "实现": impl,
            "va": impl, "status": "局部语义审阅",
            "conclusion": SEMANTICS[code],
            "unknown": "下游消息消费者与实机完成时序未在本专题全部闭环；详见中文专题记录。",
            "evidence": "专题/40EE系列事件/证据/handlers.json",
            "函数名": f.get("name"), "状态": "原证+局部语义",
            "资源索引或文案ID": strings, "构造尺寸_字节": sizes,
            "直接调用": e.get("resolved_calls", []),
            "证据文件": "handlers.json",
        })
    out = Path(__file__).parent / "证据" / "function_review.json"
    helpers = json.loads((EVIDENCE / "direct_helpers.json").read_text(encoding="utf-8"))
    records = [dict(va=f["va"], status="仅导出", conclusion="直接调用辅助函数完整原证；未凭导出量宣称全函数语义完成。", evidence="专题/40EE系列事件/证据/direct_helpers.json") for f in helpers["functions"]]
    bridges = [dict(va=e["桥接入口"], status="桥接调用局部核对", conclusion="调用对应业务handler和RTC检查；不替代业务handler审阅。", evidence="专题/40EE系列事件/证据/handlers.json") for e in selected]
    out.write_text(json.dumps({"scope": "40EE-40FE,4200-4214,5000；39事件", "entries": selected, "bridges": bridges, "helpers": records}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"entries={len(selected)}")

SEMANTICS = {
    0x40EE: "超级地雷资源500；+4/+5为库存槽/分组输入，当前角色取G+E28；+6为signed WORD目标格；6005(4B)、6007(12B动作43)、601A(8B类型27)。",
    0x40EF: "引爆卡资源501；提示后构造6061卡消耗消息；1350/1000是提示消息字段。",
    0x40F0: "净空卡资源502、RichStr330；队列包含607A(2B)清理相关消息与卡消耗。",
    0x40F1: "换位卡资源503；6000动画39与6001音效301，具体换位由消费者执行。",
    0x40F2: "乐透卡资源504；+4=-1走6060数值支路，否则按模式显示332或331并更新当前角色现金。",
    0x40F3: "女神卡资源505；6000动画5载荷type2及当前角色，动画40载荷当前角色；下游消费者决定地产加层。",
    0x40F4: "冬眠卡资源506；6001音效329、6061卡消耗及607D(2B)附加消息。",
    0x40F5: "香蕉卡资源507；6001音效307、601A载荷+2 WORD取packet+6地块，+4 BYTE=30。",
    0x40F6: "均富卡资源508；传统模式均分存款、PK均分现金；32位signed sum/idiv G+E24，商0改1，未见除零保护。",
    0x40F7: "飞吻资源1130；packet+6 signed BYTE扩展DWORD存A7E8D4，通过6000动画44发送4字节载荷。",
    0x40F8: "星光环绕资源1131；6000动画43发送当前角色G+E28的4字节载荷。",
    0x40F9: "研发中心资源509；6095载荷特殊建筑代码11。",
    0x40FA: "飞弹基地资源510；6095载荷特殊建筑代码12。",
    0x40FB: "长城资源511；6095载荷特殊建筑代码13。",
    0x40FC: "图腾柱资源512；6095载荷特殊建筑代码14。",
    0x40FD: "金字塔资源514；6095载荷特殊建筑代码16。",
    0x40FE: "空中花园资源513；6095载荷特殊建筑代码15，不能按协议顺序改成16。",
    0x4200: "股票市场参数：packet+4/+8/+12均float；+12写M+32因素、+8写M+28现值、+4写M+24前值；非正+4复用旧M+28。",
    0x4201: "股票行同步：+4 signed WORD索引、+8源结构送80F1F0；PK模式另有error game map弹框。",
    0x4202: "更新总体股票参数，packet+12起每4字节逐股送80F2D0；+52控制总体涨跌文案315/316。",
    0x4203: "packet+4股票索引和+8新价送80F2D0；按股票名和涨跌显示317/318，x87中间值不是线包字段。",
    0x4204: "股票买入：+8数量、+6股票索引、常量1、+12价格送7F9760；packet+16经60599B写P+1508最终存款。",
    0x4205: "股票卖出：+8数量、+6股票索引、常量1、+12价格送7F9850；packet+16经60599B写P+1508最终存款。",
    0x4206: "按+4文案索引排提示，末6080状态2；1800/1350为消息时长参数。",
    0x4207: "随机加盖/拆除房屋：+4 signed地块、+6方向；模式/技能限制升级，调用7E3F30/7E4020；限级失败仍排1057与6000动画7。",
    0x4208: "同街道组D+6匹配后D+5置3；地价上涨1056、6001音效316、6000动画5，末6080状态2。",
    0x4209: "全局A7EF4C/A7EF58与一次性标志A7EF64；6000动画26连续两载荷，业务命名未闭环。",
    0x420A: "+6优先于+7；前者显示RichStr342与技能资源12，后者当前角色定位并经64FB10写G+12等待500ms及G+16起始tick。",
    0x420B: "+4/+6查612443相关对象；成功600A消息16字节，+8=1与G+E28当前角色写+12。",
    0x420C: "地块+4写对象类型32、提示宝箱346；末694B90构造0002，经6BF380提交2字节上行请求；提示长度strlen+1。",
    0x420D: "signed BYTE技能+4/等级+5，+6丢弃标志；按当前等级比较选1069、347、348或349，提示3600/3600。",
    0x420E: "战斗倍率：+8且+10优先，攻击提升且防御下降文案352；单+8文案351，单+9文案350；+11持续字节。",
    0x420F: "抽奖卡出现：+4!=-1在地块设置类型33、声音14与提示805；所有分支末608A状态4。",
    0x4210: "抽奖卡分配：+4物品ID、+6单人/全体、+7+角色逐人抑制；7F8A70要求资源type=1并写8槽库存，失败可显示809，非仅满槽。",
    0x4211: "特殊装饰提示：+7丢弃1070优先，+6未激活1071，否则获得1072；本函数只显示结果。",
    0x4212: "packet+4 signed BYTE角色槽选G+E00+4*slot为this；600A 16B载荷+8 DWORD=8/+6 WORD=0/+12 BYTE=slot；7FA7B0参数packet+6 signed WORD、+5 signed BYTE。",
    0x4213: "现金事件：packet+12 signed BYTE选目标角色现金；+4>0直接6060，否则+8>0时32位imul再float落地除100加0.5取整；两项均非正仍排6000动画35。",
    0x4214: "+8/+9/+10/+11优先级四路状态，+4或+6 signed WORD幅度，+12 byte持续值。",
    0x5000: "空handler，无GmsvID校验、下游调用或状态更新；返回值不是稳定业务结果。",
}

if __name__ == "__main__":
    main()
