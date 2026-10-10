"""逐函数人工结论与原块/指令锚点绑定，分开复用记录。"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
NOTES = {
    '0x6b7d60': ('AL返回signed 0<=i<DWORD[this+5DC]，retn4；不检查基址或记录。', 'count与分配容量一致性、对象生命周期未知。'),
    '0x6b7dc0': ('直接返回DWORD[this+5D8]+124*i，retn4；不验索引、不分配不复制。', '指针有效性与32位乘加溢出由调用者约束。'),
    '0x6b7df0': ('公共索引门通过后检查记录+78 DWORD严格等1，AL布尔、retn4。', '状态值来源、其他值语义与存储有效性未全闭合。'),
    '0x6b7e70': ('公共门后比较记录+60与+3C DWORD，真实jl表示signed左>=右。', '两字段业务名称及生产来源未全闭合。'),
    '0x6b7f10': ('公共门后判断记录+60 signed DWORD>0，AL布尔、retn4。', '字段业务名称、运行初值及存储生命周期未闭合。'),
    '0x6b7f90': ('公共门后解引用记录+4指针，再取目标+20 DWORD bit0；没有内部NULL门。', '嵌套指针生命周期及flags生产未闭合。'),
    '0x734460': ('原i先过范围及非零门，取r后改用r[0]作谓词索引；依次状态/数值门选择文本547/548/550/762或UI106和末端调用。', '运行入口、记录内索引同一性、虚调用与末端深算法未闭合。'),
    '0x6a5960': ('清11计数，两轮扫CE0/F10合格记录，写借用指针列表；四分类0/1/3/4，最终列表先E70/DF0均假再至少一真。', '11缓冲分配容量、并发期间两轮一致性、底层生命周期未闭合。'),
    '0x6a39a0': ('64F090取当前对象，signed int参数fild后与对象+58 double比较，只测x87 C0决定AL，retn4。', '当前指针合法性、全局x87异常模式与double字段业务身份未闭合。'),
    '0x6a3ed0': ('局部DWORD0=r[0]、DWORD2=1；r+38等3时DWORD1=0否则6A4250(r)，然后传828F60(3,ptr)。', '6A4250算法、后续记录长度和网络语义未闭合。'),
}


def build():
    functions = []
    for name in ['formal_functions.json','dependency_raw.json']:
        payload = (HERE/name).read_bytes()
        raw = json.loads(payload)
        for index, row in enumerate(raw['functions']):
            conclusion, unknown = NOTES[row['va']]
            path, pointer = '证据/'+name, '/functions/'+str(index)
            anchors = [dict(path=path, pointer=pointer+'/assembly/'+str(n)+'/text', site_va=i['va'], value=i['text'])
                       for n,i in enumerate(row['assembly']) if i.get('is_code',True)]
            functions.append(dict(va=row['va'], name=row['name'], status='局部语义已审阅',
                                  conclusion=conclusion, unknown=[unknown], evidence=[path], anchors=anchors,
                                  declared_chunks=row['declared_chunks'], original_byte_ranges=row['chunk_byte_ranges'],
                                  source_records=[dict(path=path, sha256=hashlib.sha256(payload).hexdigest(), pointer=pointer)]))
    reused=json.loads((HERE/'reused_raw.json').read_bytes())
    result=dict(schema='richonline-function-review-1', topic='124字节共享记录与判断门',
                disk_sha256='a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2', functions=functions,
                reused=[dict(va=r['va'],source=r['source'],status='已有原证复用；新完成数0') for r in reused['records']],
                scope='固定主体及有限依赖；局部语义不代表动态功能和全生命周期闭合')
    (HERE.parent/'function_review.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return dict(fresh=len(functions),reused=len(result['reused']))


if __name__=='__main__':
    print(json.dumps(build(),ensure_ascii=True))
