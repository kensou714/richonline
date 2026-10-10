"""第29批有界采证；仅root串行运行export，本文件加载不调用IDA。"""
import hashlib
import json
import runpy
import struct
from pathlib import Path

HERE=Path(__file__).resolve().parent
DOCS=HERE.parents[2]
CORE=HERE.parents[1]/'四类型辅助请求与队列/证据/export_preparation_core.py'
SOURCE='专题/角色1416字段来源/证据/functions.json'
SOURCE_SHA='30e9cb669ab4fae9930d98cbf47349364c130ad1597b2fea216bf079d30d4224'
REUSE=((16,0x6A3C60,527,21),(17,0x6A4580,522,21),(19,0x6A6EB0,538,21))
CONFIG=dict(topic='地图摘要读取与请求生产',seeds=(0x6A3A40,),
    owner_sites=(0x6A3DF6,0x6A3E03,0x6A3E23,0x6A4611,0x6A461B,
                 0x6A4738,0x6A6F6B,0x6A6F75,0x6A7078),
    data_windows=(),reuse_navigation=(SOURCE,
        '专题/共享记录地图候选回调/证据/bounded_raw.json',
        '专题/共享记录地图候选回调/证据/boundary_data/bounded_raw.json',
        '专题/TeachMode对象与消费者/证据/teachmode_raw.json'))


def audit_reused(core):
    """只核三旧函数全部声明块，不改源、不重复导出反编译。"""
    import ida_bytes
    payload=(DOCS/SOURCE).read_bytes()
    assert hashlib.sha256(payload).hexdigest()==SOURCE_SHA
    old=json.loads(payload)
    image=(core['ROOT']/'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest()==core['EXPECTED_SHA']
    pe=struct.unpack_from('<I',image,60)[0]
    base=struct.unpack_from('<I',image,pe+52)[0]
    table=pe+24+struct.unpack_from('<H',image,pe+20)[0]
    sections=[struct.unpack_from('<4I',image,table+40*i+8)
              for i in range(struct.unpack_from('<H',image,pe+6)[0])]
    result=[]
    for index,va,size,tail_size in REUSE:
        f=old['functions'][index]
        assert int(f['va'],16)==va and f['status']=='仅导出'
        assert int(f['end_va'],16)-va==size
        chunks=f['chunk_byte_ranges']
        assert sorted(c['size'] for c in chunks)==sorted((size,tail_size))
        audits=[]
        for i,b in enumerate(chunks):
            at=int(b.get('start_va',b.get('va')),16)
            blob=bytes.fromhex(b['idb_hex'])
            assert len(blob)==b['size'] and blob.hex()==b['disk_hex'] and b['matching']
            offsets=[off+at-base-rva for _,rva,length,off in sections
                     if 0<=at-base-rva and at-base-rva+len(blob)<=length]
            assert len(offsets)==1
            current=ida_bytes.get_bytes(at,len(blob))
            assert current==blob==image[offsets[0]:offsets[0]+len(blob)],hex(at)
            audits.append(dict(start_va=hex(at),size=len(blob),current_idb_hex=current.hex(),
                current_disk_hex=blob.hex(),matching=True,sha256=hashlib.sha256(blob).hexdigest(),
                source_pointer=f'/functions/{index}/chunk_byte_ranges/{i}'))
        result.append(dict(seed_va=hex(va),source_path=SOURCE,source_pointer=f'/functions/{index}',
            source_sha256=SOURCE_SHA,original_status=f['status'],current_byte_audits=audits,
            pending_status='旧完整原证当前补核；语义升级待作者及独审，不计新增导出'))
    return result


def export():
    output=HERE/'bounded_raw.json'
    assert not output.exists(),'禁止覆盖既有原证'
    core=runpy.run_path(str(CORE))
    reused=audit_reused(core)
    report=core['export'](CONFIG,HERE)
    raw=json.loads(output.read_bytes())
    raw['reused_source_byte_audits']=reused
    raw['prepared_wrapper_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    output.write_text(json.dumps(raw,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    return dict(report,reused_source_count=len(reused),prepared_wrapper_sha256=raw['prepared_wrapper_sha256'])
