"""第28批有限采证；仅主代理串行调用export，加载本文件不访问IDA。"""
import hashlib
import json
import runpy
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
DOCS = HERE.parents[2]
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
REUSE = (
    ('专题/角色1416字段来源/证据/functions.json', '/functions/18', 0x6A54F0),
    ('专题/随机地图候选与配置索引/证据/functions_raw.json', '/functions/6', 0x6AAA80),
    ('专题/录像文件与执行链/证据/io_and_parser_navigation.json', '/functions/21', 0x7E71E0),
    ('专题/地图与路径/证据/map_runtime_core.json', '/函数/2', 0x7DED90),
)
CONFIG = dict(
    topic='共享记录地图候选回调',
    seeds=(0x6BA170, 0x6AAA40),
    owner_sites=(0x6A55A3,0x6A55EB,0x6A5633,0x6A567B,0x6A56C3,
                 0x6A570B,0x6A5753,0x6A579B,0x6A57E3,0x6A582B,
                 0x6A5898,0x7E7236),
    data_windows=(),
    reuse_navigation=tuple(path for path, _, _ in REUSE),
)


def audit_reused(core):
    """逐块补核旧原证；中文路径函数逐指令核对，不重复导出伪码。"""
    import ida_bytes
    image = (core['ROOT']/'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest()==core['EXPECTED_SHA']
    pe=struct.unpack_from('<I',image,0x3C)[0]
    base=struct.unpack_from('<I',image,pe+52)[0]
    table=pe+24+struct.unpack_from('<H',image,pe+20)[0]
    sections=[struct.unpack_from('<4I',image,table+40*i+8)
              for i in range(struct.unpack_from('<H',image,pe+6)[0])]
    results=[]
    for path,pointer,va in REUSE:
        payload=(DOCS/path).read_bytes()
        old=json.loads(payload)
        for part in pointer.strip('/').split('/'):
            old=old[int(part)] if isinstance(old,list) else old[part]
        assert int(old.get('va',old.get('地址')),16)==va
        if '完整汇编' in old:
            blocks=[dict(start_va=row['地址'],size=len(bytes.fromhex(row['字节核验']['IDB字节'])),
                         idb_hex=row['字节核验']['IDB字节'],disk_hex=row['字节核验']['磁盘字节'],
                         matching=row['字节核验']['匹配'],source_pointer=pointer+f'/完整汇编/{i}')
                    for i,row in enumerate(old['完整汇编'])]
        else:
            key='chunk_byte_ranges' if old.get('chunk_byte_ranges') else 'byte_ranges'
            blocks=[dict(block,source_pointer=pointer+f'/{key}/{i}') for i,block in enumerate(old[key])]
        audits=[]
        for block in blocks:
            at=int(block.get('start_va',block.get('va')),16)
            blob=bytes.fromhex(block['idb_hex'])
            assert block['matching'] and blob==bytes.fromhex(block['disk_hex']) and len(blob)==block['size']
            offsets=[off+at-base-rva for _,rva,count,off in sections
                     if 0<=at-base-rva and at-base-rva+len(blob)<=count]
            assert len(offsets)==1
            current=ida_bytes.get_bytes(at,len(blob))
            assert current==blob==image[offsets[0]:offsets[0]+len(blob)],hex(at)
            audits.append(dict(start_va=hex(at),size=len(blob),current_idb_hex=current.hex(),
                current_disk_hex=blob.hex(),matching=True,sha256=hashlib.sha256(blob).hexdigest(),
                source_pointer=block['source_pointer']))
        results.append(dict(seed_va=hex(va),source_path=path,source_pointer=pointer,
            source_sha256=hashlib.sha256(payload).hexdigest(),original_status=old.get('status',old.get('状态')),
            current_byte_audits=audits,pending_status='旧原证当前补核；不是新增导出或新增审阅'))
    return results


def export():
    output=HERE/'bounded_raw.json'
    assert not output.exists(),'禁止覆盖既有原证'
    core=runpy.run_path(str(CORE))
    reused=audit_reused(core)
    report=core['export'](CONFIG,HERE)
    result=json.loads(output.read_bytes())
    result['reused_source_byte_audits']=reused
    result['prepared_wrapper_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    return dict(report,reused_source_count=len(reused),prepared_wrapper_sha256=result['prepared_wrapper_sha256'])
