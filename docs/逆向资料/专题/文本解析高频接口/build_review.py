"""生成逐函数人工审阅索引；仅导出项保留空结论。"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent

CONCLUSIONS = {
    0x90F150: 'Section+8/+12指针数组线性查Entry，非空名字经_stricmp匹配即返回首个借用对象；失败0，无持续游标。',
    0x90FA00: 'Config+4/+8指针数组线性查Section，非空名字经_stricmp匹配即返回首个借用对象；失败0，不创建。',
    0x82A900: '仅返回DWORD[this+80]；代表调用链上this来自Manager+32，未闭合真实类型与字段填充者。',
    0x82AB80: '仅返回DWORD[this+32]；代表调用者以ACBB30单例为this，返回值继续作为82A900的ECX。',
    0x82A940: '仅返回DWORD[this+4]；不将同偏移解释成全局一致的业务成员。',
    0x82A980: '仅返回DWORD[this+12]；只核访问器，不恢复全部调用者类型。',
    0x82AA00: '仅返回DWORD[this+24]；828F60 case34中this来自82A900返回对象。',
    0x82AB40: '仅返回DWORD[this+44]；对象语义未恢复。',
    0x90EA40: '清零this的两个DWORD；虽然IDA误名ReaderWriterLock，局部调用链为8B键值对象初始化。',
    0x90EA60: '清名字/值指针后调用90EB70、90EC30分别复制两个字符串。',
    0x90EAA0: '清名字/值指针后复制名字，再经90ECF0把整数格式化为字符串值。',
    0x90EAE0: 'E9链经6034AC至90EB00；只作析构包装桥接，不是另一种资源释放策略。',
    0x90EB00: '依次delete名字与值并置NULL；只释放Entry拥有的两段字符串，不释放Entry本体。',
    0x90EB50: '返回Entry首DWORD名字借用指针，不复制不转码。',
    0x90EB70: '名字非空才先删旧再分配strlen+1并复制；空输入保留旧名，输入别名旧缓冲不安全。',
    0x90EC10: '返回Entry+4值借用指针，可为NULL。',
    0x90EC30: '先删旧值并置NULL，非空输入才重新分配复制；空值归一成NULL，输入别名旧缓冲不安全。',
    0x90ECC0: '值非NULL时调用atoi，NULL返回0；不能由返回0区分空值和合法数值0。',
    0x90ECF0: '以%d格式化到共享全局暂存，再交90EC30复制；本函数未提供锁或独立线程暂存。',
    0x90ED30: '清Section名字与+8/+12/+16三个容器指针；先push ecx后从[esp+3]取this最高字节写+4，机械来源已知，业务用途未知。',
    0x90ED60: '调用90EDE0清节和Entry，再delete指针数组并清begin/end/capacity_end；含异常尾块原证。',
    0x90EDE0: '删除节名与每个Entry及字符串，清槽，令end=begin保留数组容量。',
    0x90EEA0: 'Section begin非NULL时返回(end-begin)>>2，否则0。',
    0x90EED0: '返回Section首DWORD名字借用指针。',
    0x90EEF0: '非空节名先释放旧名再分配复制；NULL/空输入返回0并保留原名。',
    0x90F110: 'Entry索引读取：负数、begin为NULL或越界返回0；合法索引返回借用Entry*。',
    0x90F1D0: '同名Entry更新字符串值并保留原名，未命中分配8B对象并追加；数组搬移/异常安全未全闭合。',
    0x90F4D0: '同名Entry通过整数setter更新，不存在分配8B对象再追加；数组搬移辅助只导出。',
    0x90F7D0: '48B Config初始化指针树和四个暂存指针；容量1102/256/256/256；首BYTE取刚push ecx的this最高字节，业务用途未知。',
    0x90F820: '清Section树，释放四暂存和Section指针数组并清三容器指针；含异常尾块原证。',
    0x90F8F0: '逐Section调用析构并delete，清数组槽，再令end=begin。',
    0x90F990: 'Config begin非NULL时返回(end-begin)>>2，否则0。',
    0x90F9C0: 'Section索引读取：负数、begin为NULL或越界返回0，合法返回借用Section*。',
    0x90FA80: '同名节直接返回，未命中分配20B Section、复制节名并追加；分配失败没有完整回滚保证。',
    0x90FEC0: '两名字非空后依次找节/键并检查NULL，最后借出字符串；缺失或空值都可返回NULL。',
    0x90FF40: '两名字非空后取或建Section，再更新字符串Entry；不能把返回寄存器当可靠成功标志。',
    0x90FFB0: '依次检查名字和查询结果，再从Entry转整数；失败返回0，与合法0不区分。',
    0x9100A0: 'rt逐字节读行，丢TAB，首分号注释、整行方括号节、首等号键值；不清旧树，行末NUL存在等容量越界路径。',
    0x910450: 'w按树顺序输出节与键值、每节多空行；不保留原格式、不转义，未传播写入失败。',
    0x9105D0: 'rb读取并循环逐BYTE减key后采用同形行解析；key索引跨行，未主动清CR或旧树，错误语义仍局部。',
    0x9109D0: 'wb格式化节键后循环逐BYTE加key，key索引连续；没有明文保存器节末额外空行，未传播短写。',
    0x94E560: '使用当前线程locale；locale字段+20为0走ASCII比较，否则逐unsigned BYTE调tolower_mt。未证明运行代码页。',
    0x94E4F0: 'ASCII不区分大小写比较只折叠A..Z，高位字节不作Unicode处理；按NUL终止。',
    0x947ED0: 'locale相关小写转换可用字符表/LCMapStringA及locale codepage；本专题只核比较路径，不展开整个CRT本地化。',
    0x8E4AD0: '以管理器+104持有48B Config；明文或循环key装载，Head及尺寸类型建UI，成功销毁Config；失败可保留旧树。',
    0x8E4DC0: '按Parent筛Section并读位置尺寸类型建子节点；部分查询结果直接解引用，必要键约束由消费者承担。',
    0x828F60: '仅核case34的ACBB30->+32->+80->+24 ECX链；大型分派其余分支仅导出，不能记为全审阅。',
    0x8976E0: '标志ACBB2C控制ACBB30单例构造及atexit登记；只核单例获取边界。',
    0x897440: '单例构造中明确写this+32=0；基类与其它初始化调用未展开，字段填充者仍未知。',
}


def build():
    inventory = {}
    for path in sorted((HERE / '证据').glob('*.json')):
        data = json.loads(path.read_text(encoding='utf-8'))
        for f in data.get('functions', []):
            inventory.setdefault(int(f['va'], 16), []).append('证据/' + path.name)
    if set(CONCLUSIONS) - set(inventory):
        raise ValueError('结论缺少原证')
    rows = [dict(va=hex(va), status='局部语义已审阅' if va in CONCLUSIONS else '仅导出',
                 conclusion=CONCLUSIONS.get(va), evidence=paths,
                 unknown='静态分析；调用者完整参数约束、资源代码页、异常/内存不足、间接调用与运行行为未全闭合。'
                 if va in CONCLUSIONS else '仅保存全块原证，不计入人工语义审阅。')
            for va, paths in sorted(inventory.items())]
    result = dict(scope='高频名称查询、配置树生命周期、装载保存及访问器局部归属',
                  exported_function_count=len(inventory), local_review_count=len(CONCLUSIONS),
                  warning='仅导出、局部语义审阅和实机验收是不同状态，不将邻接或高引用视为业务语义。',
                  functions=rows)
    (HERE / '函数审阅清单.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({k: v for k, v in result.items() if k != 'functions'}, ensure_ascii=False))


if __name__ == '__main__':
    build()
