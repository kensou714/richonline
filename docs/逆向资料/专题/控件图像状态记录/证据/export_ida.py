"""只读导出图片状态记录及回调消费群；不改EXE、IDB或中央台账。"""
from pathlib import Path
import json

ROOT=Path('F:/大富翁online/Richonline')
BASE=ROOT/'docs/逆向资料/专题/控件图像状态记录/证据'
SEEDS={0x8E1C40,0x8E1C70,0x8E1D10,0x8E1DB0,0x8E1EF0,0x8E1F20,
       0x8E1F50,0x8E1F80,0x8E1FB0,0x8E21D0,0x8E2200,0x8E2230}

def export(db):
    ns={}
    exec((ROOT/'docs/逆向资料/全量分析/export_function_group.py').read_text('utf-8'),ns)
    result=ns['export_group'](db,SEEDS,str(BASE/'functions_raw.json'))
    bridges=[]
    inbound=[]
    # 入口桥和全部入边仅作导航，不批量导出调用者函数。
    for address in sorted(SEEDS):
        for x in db.xrefs.to_ea(address):
            raw=db.bytes.get_bytes_at(x.from_ea,5)
            if raw and raw[0]==0xE9 and x.from_ea+5+int.from_bytes(raw[1:],'little',signed=True)==address:
                bridges.append(dict(va=hex(x.from_ea),size=5,idb_hex=raw.hex(),target=hex(address)))
                for y in db.xrefs.to_ea(x.from_ea):
                    owner=db.functions.get_at(y.from_ea)
                    inbound.append(dict(site=hex(y.from_ea),target=hex(x.from_ea),kind=int(y.type),
                                        owner=hex(owner.start_ea) if owner else None,
                                        idb_hex=db.bytes.get_bytes_at(y.from_ea,5).hex()))
    # 已有列表依赖的一个实际调用邻域，展示保留ECX且不作为完整调用者审阅。
    windows=[]
    for start,end in [(0x8F8B5A,0x8F8B7F)]:
        windows.append(dict(start_va=hex(start),end_va=hex(end),size=end-start,
                            idb_hex=db.bytes.get_bytes_at(start,end-start).hex(),
                            assembly=[dict(va=hex(i.ea),text=db.instructions.get_disassembly(i))
                                      for i in db.instructions.get_between(start,end)]))
    data=[]
    for address in [0xA67AA0]:
        raw=db.bytes.get_bytes_at(address,128)
        raw=raw[:raw.index(0)+1]
        data.append(dict(va=hex(address),size=len(raw),idb_hex=raw.hex()))
    # 另一个诊断字符串地址从真实指令数据引用获取，不猜符号位置。
    for i in db.instructions.get_between(0x8E1FB0,0x8E215A):
        text=db.instructions.get_disassembly(i)
        if 'offset OutputString' in text:
            for x in db.xrefs.from_ea(i.ea):
                if x.type not in (16,17,18,19,21):
                    raw=db.bytes.get_bytes_at(x.to_ea,128)
                    raw=raw[:raw.index(0)+1]
                    entry=dict(va=hex(x.to_ea),size=len(raw),idb_hex=raw.hex())
                    if entry not in data:data.append(entry)
    (BASE/'navigation.json').write_text(json.dumps(dict(bridges=bridges,inbound=inbound,windows=windows,data=data),ensure_ascii=False,indent=2)+'\n','utf-8')
    return dict(functions=result,entry_bridges=len(bridges),inbound_records=len(inbound),windows=len(windows),data=len(data))

def supplement(db):
    ns={}
    exec((ROOT/'docs/逆向资料/全量分析/export_function_group.py').read_text('utf-8'),ns)
    # 四项明确复用：注册器与三个setter；四项补图片状态复制及实际回调消费。
    addresses={0x8E1930,0x6E2E60,0x8E86A0,0x8E86C0,0x8E8620,0x6E4D00,0x6E4D40,0x6E51D0}
    result=ns['export_group'](db,addresses,str(BASE/'callbacks_raw.json'))
    bridges=[]
    for address in [0x607E6C,0x60BC74,0x6096EF]:
        raw=db.bytes.get_bytes_at(address,5)
        assert raw[0]==0xE9
        bridges.append(dict(va=hex(address),size=5,idb_hex=raw.hex(),target=hex(address+5+int.from_bytes(raw[1:],'little',signed=True))))
    (BASE/'callback_bridges.json').write_text(json.dumps(bridges,ensure_ascii=False,indent=2)+'\n','utf-8')
    return result
