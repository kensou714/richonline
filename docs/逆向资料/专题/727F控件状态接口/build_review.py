"""生成逐函数状态；全读原证不等于依赖与运行场景完全闭合。"""
import json
from evidence_sources import HERE, records

PARTIAL = {0x8FAE70,0x7113A0,0x712750}
CONCLUSIONS = {
    0x727F10: '透传this与行参数至727F50，EAX返回同一个失效栈地址。',
    0x727F50: '8F4050读取行宽文本后交8E0590，未建立结果所有权。',
    0x728060: '读取DWORD[this+348]至EAX；几何写入端证明其为局部Y。',
    0x728120: '读取DWORD[this+344]至EAX；几何写入端证明其为局部X。',
    0x727EC0: 'ECX透传，窄转宽共享缓冲交8FAE70，第二参数只保证低byte。',
    0x727F90: 'fld dword ptr[this+540]，返回x87 ST(0)；字段业务含义未证。',
    0x727FC0: '读取this+6至AL；输入对象消费及写入端确认左键双击沿。',
    0x727FE0: '窄转宽共享缓冲交8F41B0分行追加，ECX及低byte保持。',
    0x728150: 'this+3744+10000*row+2*col处WORD递增回绕；EAX返回col。',
    0x7281B0: '同计数地址以movzx读取WORD，返回0..65535。',
    0x728220: '数组this+4的388字节记录+384不等于-1时AL=1，无索引保护。',
    0x8E0590: 'CP_ACP或可选回调宽转窄到260B局部数组，返回前释放自身栈帧。',
    0x8FAE70: '编辑宽文本局部插入顺序、10240WCHAR临时区和无总容量验证已证。',
    0x7113A0: '复核卡片专题消费者：限次用32位count+1检查，回调结果0且已启用限制时WORD递增。',
    0x712750: '遍历2..6读取388B记录谓词，并结合另一条件设置UI虚表+200。',
    0x8E31B0: '复核+344 X写入、几何限位与关联移动；完整依赖沿用原专题。',
    0x8E3340: '复核+348 Y写入、几何限位与关联移动；完整依赖沿用原专题。',
    0x715140: '复核两坐标getter与随机位移setter的代表数据流。',
    0x8E0650: '复核窄转宽共享全局缓冲与可选回调；不同于8E0590局部栈。',
    0x8F4050: '复核有符号上界及160B行记录+8宽文本指针；负索引不被拒绝。',
    0x8F41B0: '复核LF/可选反斜杠n的临时分割、虚调用及恢复。',
    0x736D10: '复核627270返回输入对象后调用727FC0的接收对象来源。',
    0x81DCA0: '复核WM_LBUTTONDBLCLK向输入对象+6写1；原输入专题不重复计数。',
    0x81DEC0: '复核帧清理向输入对象+6写0；原输入专题不重复计数。',
}


def build():
    rows = []
    for entry in records():
        f = entry['function']
        va = int(f['va'],16)
        status = '既有专题局部复核' if entry['reused'] else ('局部静态契约部分完成' if va in PARTIAL else '局部静态契约已完成')
        rows.append(dict(va=f['va'],status=status,newly_analyzed=not entry['reused'],
                         conclusion=CONCLUSIONS[va],
                         unknown=('外部回调、业务索引范围、动态状态和完整通知生命周期未闭合。' if va in PARTIAL else
                                  '函数局部契约不证明全部调用者或外部依赖安全；字段单位不凭自动名推断。'),
                         evidence=entry['source']+'#'+entry['pointer'],
                         source_fingerprint=entry['source_fingerprint'],
                         prior_review='../道具与卡片操作/函数审阅清单.json#/19' if va==0x7113A0 else None,
                         declared_chunks=f.get('declared_chunks'),
                         exported_byte_ranges=[dict(va=r['va'],size=r['size']) for r in f['byte_ranges']],
                         declared_bytes=sum(int(c['end_va'],16)-int(c['start_va'],16) for c in f.get('declared_chunks',[]))))
    payload=dict(disk_sha256='a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2',
                 functions=rows, limitation='旧输入原证整文件IDB指纹不同；仅按本专题逐范围与当前PE复核，不替换来源指纹。')
    (HERE/'function_review.json').write_text(json.dumps(payload,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
    lines=['// ============================================================================','// 727F接口逐函数结论 / 由build_review.py生成','// ============================================================================']
    for row in rows:
        lines += ['//',f"// {row['va']} / {row['status']}",'// '+row['conclusion'],'// 未决：'+row['unknown'],'// 原证：'+row['evidence']]
    (HERE/'05_逐函数结论.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8',newline='\n')
    return payload


if __name__=='__main__':
    print(len(build()['functions']))
