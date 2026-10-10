"""人工语义结论配合机械来源绑定；不由导出状态自动升级。"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
NOTES = {
    '0x709e50': ('初始化四费用缓存，按特殊模式、P150、P0E0分支读取四槽；三次signed金额门影响控件状态，半价缓存向零除2。', '特殊对象获取、深车辆谓词、虚表实现及运行回调可达性未全闭合。'),
    '0x70a7e0': ('按参数首DWORD的0/1保存恢复三BYTE状态，2按三个金额门修正控件状态；G0不足但控件2状态零仍继续查G1。', '控件虚+C8/虚+78完整合同、通知来源与运行时同步未闭合。'),
    '0x70aba0': ('分派控件1/2/3提交选择，4按金额及三角色BYTE门开提示或控制面板，21..26提交1..6；本地记录6字节末位CC。', '顶层运行回调来源、深层谓词、6BF380以后联网和服务器扣款未闭合。'),
    '0x70b050': ('727CC0写WORD0=20，再写根对象内嵌标识低WORD至+2与选择低BYTE至+4，以长度6送6BF380；+5保留CC，无金额。', '本地事件下游消费与实际网络布局未在本批闭合。'),
    '0x727cc0': ('ECX目标首WORD写20，返回ECX目标地址；不清零其余字节，普通retn。', '调用方目标容量与最终事件消费由外部保证。'),
    '0x63e080': ('signed DWORD[this+A0]>0返回AL，普通retn；决定当前分支是否跳金额门。', 'A0写入来源、完整游戏意义及服务器对应权威未闭合。'),
    '0x727ae0': ('返回DWORD[this+134]，普通retn。', '该图像值全体生产者与资源映射未在本批核全。'),
    '0x727ba0': ('返回DWORD[this+10C]，普通retn。', '该图像值全体生产者与资源映射未在本批核全。'),
    '0x727c00': ('signed BYTE[this+5DA]转非零BOOL，无写入，普通retn。', '5DA具体状态命名及生产端未闭合。'),
    '0x727c30': ('signed BYTE[this+5DD]>0返回BOOL，无写入，普通retn。', '5DD具体状态命名及生产端未闭合。'),
    '0x727c60': ('signed BYTE[this+5DE]>0返回BOOL，无写入，普通retn。', '5DE具体状态命名及生产端未闭合。'),
    '0x727c90': ('ECX目标首WORD写22，返回目标地址，不清余字节，普通retn。', '调用方目标容量与事件下游由外部保证。'),
    '0x5ffd89': ('直接E9跳向6EEC70，已核当前磁盘。', '仅桥，不计新增业务完成。'),
    '0x601f7b': ('直接E9跳向6EEC20，已核当前磁盘。', '仅桥，不计新增业务完成。'),
    '0x604fb9': ('直接E9跳向6EEBD0，已核当前磁盘。', '仅桥，不计新增业务完成。'),
    '0x6eebd0': ('push1后调用6279C0，再以其返回值作ECX调用64F060，将原调用参数转发所得对象虚+64；cdecl普通retn。', '常量1所属被调接口、运行时虚表与费用缓存显示关联未闭合。'),
    '0x6eec20': ('push1后调用6279C0，再以其返回值作ECX调用64F060，将原调用参数转发所得对象虚+6C；cdecl普通retn。', '常量1所属被调接口、运行时虚表与费用缓存显示关联未闭合。'),
    '0x6eec70': ('push1后调用6279C0，再以其返回值作ECX调用64F060，将原调用参数转发所得对象虚+90；cdecl普通retn。', '常量1所属被调接口、运行时虚表与费用缓存显示关联未闭合。'),
    '0x7b9ca0': ('复用装载器补当前PE完整声明块；ITEM indx/charge经128容量文本转atoi后直接写A87480索引DWORD，无本地范围门。', '解析器失败/畸形输入、真实数组容量与运行加载结果未闭合；复用不计新入口。'),
}


def build():
    sources = ['formal_functions.json', 'dependency_raw.json']
    for extra in ('display_loader_raw.json',):
        if (HERE / extra).exists():
            sources.append(extra)
    functions = []
    for name in sources:
        payload = (HERE / name).read_bytes()
        raw = json.loads(payload)
        for index, row in enumerate(raw['functions']):
            conclusion, unknown = NOTES[row['va']]
            path = '证据/' + name
            pointer = '/functions/' + str(index)
            anchors = [dict(path=path, pointer=pointer+'/assembly/'+str(n)+'/text',
                            site_va=i['va'], value=i['text']) for n, i in enumerate(row['assembly'])
                       if i.get('is_code', True)]
            category = '桥接复核' if row['va'] in ('0x5ffd89','0x601f7b','0x604fb9') else '已有入口补证' if row['va'] == '0x7b9ca0' else '新入口局部审阅'
            functions.append(dict(va=row['va'], name=row['name'], status='局部语义已审阅', counting_category=category,
                                  conclusion=conclusion, unknown=[unknown], evidence=[path], anchors=anchors,
                                  declared_chunks=row['declared_chunks'], original_byte_ranges=row['chunk_byte_ranges'],
                                  source_records=[dict(path=path, sha256=hashlib.sha256(payload).hexdigest(), pointer=pointer)]))
    reused = json.loads((HERE/'reused_raw.json').read_bytes())
    result = dict(schema='richonline-function-review-1', topic='GoldCharge四槽与金额消费',
                  disk_sha256='a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2',
                  functions=functions,
                  reused=[dict(va=r['va'], source=r['source'], status='已有原证复用；新完成数0') for r in reused['records']],
                  scope='固定种子与有限依赖；局部语义审阅不代表整条游戏流程或网络已完成')
    (HERE.parent/'function_review.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    return dict(declared_records=len(functions), fresh=sum(r['counting_category']=='新入口局部审阅' for r in functions), reused=len(result['reused']))


if __name__ == '__main__':
    print(json.dumps(build(), ensure_ascii=True))
