"""第二十五批共享数组固定范围；加载不访问IDA，桥端点不算新主体。"""
import hashlib
import json
import runpy
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
CORE = HERE.parents[1]/'四类型辅助请求与队列/证据/export_preparation_core.py'
FIXED_SOURCES = (
    ('邮件与礼物分组/证据/functions.json','/functions/1','0x69e600','12d7ba17dc41cfcacc096c4bd24793fe59606f4dbc9ddc34354f4ec1d4fb30f4'),
    ('游戏时间与计时调度/证据/functions.json','/functions/5','0x6ab5f0','ddebd0cf95aef329a7749e27aad8bf6f968029e50df18d0b7b092b28113d964b'),
    ('TeachMode状态与序号来源/证据/producers_raw.json','/functions/0','0x69df50','06cc3158681987faa7b122997b9435bde2d2f851d462e9e22fc32aa56635661c'),
    ('TeachMode状态与序号来源/证据/closure_raw.json','/functions/0','0x628270','de7cbac38a2508db330f6fba2de59879c2a734ac55d737377fa06ea59f7f8a97'),
    ('MapView配置记录与预览消费/证据/functions_raw.json','/functions/0','0x622d50','027d4e07571910bece1b5348be77dcbd940f59b606a8097bc6290e95e06f2101'),
)
CONFIG = dict(
    topic='124字节共享数组生命周期',
    seeds=(0x6A4A80,0x6A4860,0x6B7CB0,0x69E600,0x6AB5F0),
    owner_sites=(0x69E4CC,0x69E50D),
    data_windows=(),
    reuse_navigation=(
        '专题/邮件与礼物分组/证据/functions.json',
        '专题/游戏时间与计时调度/证据/functions.json',
        '专题/TeachMode状态与序号来源/证据/producers_raw.json',
        '专题/TeachMode状态与序号来源/证据/closure_raw.json',
        '专题/MapView配置记录与预览消费/证据/functions_raw.json',
        '专题/124字节共享记录与判断门/证据/formal_functions.json',
        '专题/124字节共享记录内容写入/证据/formal_functions.json',
    ),
)


def callback_bridge(image):
    import ida_bytes
    import ida_funcs
    import idautils
    pe = struct.unpack_from('<I',image,0x3C)[0]
    base = struct.unpack_from('<I',image,pe+52)[0]
    table = pe+24+struct.unpack_from('<H',image,pe+20)[0]
    sections = [struct.unpack_from('<4I',image,table+i*40+8) for i in range(struct.unpack_from('<H',image,pe+6)[0])]
    rows, seen, ea = [], set(), 0x60D34E
    while True:
        assert ea not in seen, ('回调桥循环',hex(ea))
        seen.add(ea)
        raw = ida_bytes.get_bytes(ea,5)
        assert raw is not None and len(raw)==5, ('无回调端点字节',hex(ea))
        if raw[0]!=0xE9:
            break
        owner = ida_funcs.get_func(ea)
        if owner is None or owner.start_ea!=ea or list(idautils.Chunks(ea))!=[(ea,ea+5)]:
            break
        assert len(rows)<16, '回调E9链超过有限上限'
        matches = [(rva,off) for _,rva,length,off in sections if 0<=ea-base-rva and ea-base-rva+5<=length]
        assert len(matches)==1, ('桥无唯一磁盘范围',hex(ea))
        rva,off = matches[0]
        current = image[off+ea-base-rva:off+ea-base-rva+5]
        assert current==raw, ('回调桥磁盘/IDB不一致',hex(ea))
        target = ea+5+struct.unpack_from('<i',raw,1)[0]
        rows.append(dict(start_va=hex(ea),size=5,idb_hex=raw.hex(),disk_hex=current.hex(),
                         matching=True,sha256=hashlib.sha256(raw).hexdigest(),target_va=hex(target),
                         pending_status='仅核直接E9桥；端点完整语义待审'))
        ea = target
    assert rows, '60D34E不是独立直接E9桥，先报告，不以邻接推定目标'
    return dict(schema='richonline-finite-callback-bridge-preparation-1',disk_sha256=EXPECTED_SHA,
                seed_va='0x60d34e',endpoint_seed_va=hex(ea),bridges=rows,
                pending_status='仅有限桥原证；不增加主体/业务语义完成数')


def export():
    assert not (HERE/'bounded_raw.json').exists(), '禁止覆盖既有采证'
    assert not (HERE/'callback_bridge.json').exists(), '禁止覆盖既有回调桥原证'
    image = (ROOT/'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest()==EXPECTED_SHA
    for name,pointer,seed,sha in FIXED_SOURCES:
        payload = (HERE.parents[1]/name).read_bytes()
        assert hashlib.sha256(payload).hexdigest()==sha, ('旧来源变更，先重新准备',name)
        row = json.loads(payload)
        for part in pointer.strip('/').split('/'):
            row = row[int(part)] if isinstance(row,list) else row[part]
        assert row['va']==seed, (name,pointer,seed)
    supplement = callback_bridge(image)
    report = runpy.run_path(str(CORE))['export'](CONFIG,HERE)
    (HERE/'callback_bridge.json').write_text(json.dumps(supplement,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return dict(report,callback_bridge_count=len(supplement['bridges']),
                prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
