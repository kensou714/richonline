"""银行专题人工职责索引；字节一致与语义审阅独立记录。"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REVIEW = {
    '0x65e1b0': ('已分析', '校验GmsvID，位置不符重排8字节记录，否则开UI17并设pending16'),
    '0x660320': ('已分析', '按当前行动角色结算存取，清pending，分中途恢复和6080继续'),
    '0x64f710': ('已分析', '回复身份与G+83844比较，不同弹错并拒绝'),
    '0x63e410': ('已分析', '读取角色+1464当前位置DWORD'),
    '0x693cb0': ('已分析', '写G+83832银行中途标志BYTE'),
    '0x63f760': ('已分析', '比较当前行动槽G+3624与本地槽G+8'),
    '0x7bb430': ('已分析', '写pending类型/持续值/开始Tick，末实参未使用'),
    '0x693c80': ('已分析', '仅写WORD消息号4018'),
    '0x7f9f10': ('已分析', '32位减存款，signed负值归0，可选金额显示通知'),
    '0x7fa050': ('已分析', '32位加现金，可选显示通知，无余额上夹'),
    '0x7f83f0': ('已分析', '减现金不足时以负余数减存款，并返回余额耗尽标志'),
    '0x7fa0a0': ('已分析', '32位加存款，可选显示通知，无余额上夹'),
    '0x6939e0': ('已分析', '清pending类型为-1和持续值0，起Tick不改'),
    '0x7f5cc0': ('局部已分析', '核对运动恢复字段+548/+552；内部状态setter的业务语义跨专题'),
    '0x693fb0': ('已分析', '角色+1456字节按输入低字节相加'),
    '0x7f7160': ('局部已分析', '返回100/120/121音效号，分支谓词业务含义待动作专题'),
    '0x693be0': ('已分析', '构造6080并置+3=-1，其他字节不初始化'),
    '0x7bbe60': ('已分析', '构造12字节0027请求，(1,0)取全存款；仅本地行动者发送关UI'),
    '0x7d5fc0': ('已分析', '仅写WORD消息号0027'),
    '0x63f650': ('已分析', '读取角色+1508存款DWORD'),
    '0x6fb280': ('局部已分析', '调用窗口基类构造并设银行虚表A24FD0'),
    '0x713c00': ('已分析', '银行通知设取款模式/零金额，保存角色槽和两账户快照'),
    '0x713d20': ('已分析', '主状态2下按键映射控件，Esc提交退出并清pending'),
    '0x714080': ('已分析', '银行按钮ID分派、32位金额编辑/比例、快照限制及请求提交'),
    '0x714610': ('已分析', '现金/存款快照以十进制显示于控件40/41'),
    '0x7144a0': ('局部已分析', '根据模式切换30/31控件虚表+196状态，虚方法完整语义未闭合'),
    '0x714540': ('已分析', '编辑金额以十进制写控件43'),
    '0x63f620': ('已分析', '读取角色+1504现金DWORD'),
    '0x63e440': ('已分析', '读取所给子对象+4 DWORD，不凭getter命名业务身份'),
    '0x63e5b0': ('已分析', 'G+640队列子对象经getter取当前head'),
    '0x6bf380': ('局部已分析', '发送包装主状态/连接门槛与交接，编码/传输下游另见网络专题'),
    '0x63f940': ('已分析', '读取子对象+12 DWORD，本链为队列head'),
}

def main():
    records = {}
    for path in sorted((ROOT / '证据').glob('bank_*.json')):
        for item in json.loads(path.read_text(encoding='utf-8'))['functions']:
            va = item['va']
            status, conclusion = REVIEW[va]
            row = records.setdefault(va, dict(va=va, status=status, conclusion=conclusion,
                evidence=[], document=['00_银行等待与回复闭环.txt','01_银行界面金额与请求构造.txt'],
                unknown=['未实机验证；完整上游输入域及跨线程时序不由本条局部审阅证明']))
            row['evidence'].append(path.relative_to(ROOT).as_posix())
    if set(records) != set(REVIEW):
        raise ValueError('清单与人工结论集合不一致')
    output = dict(scope='函数内行为已读与关键汇编已核；下游契约仍按文档边界',
                  functions=sorted(records.values(), key=lambda r:int(r['va'],16)))
    (ROOT/'函数审阅清单.json').write_text(json.dumps(output,ensure_ascii=False,indent=2),encoding='utf-8')
    print('functions',len(records))

if __name__ == '__main__':
    main()
