"""两新本体与十旧窄契约分列，不将机械记录或窗口提升为业务覆盖。"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    new = json.loads((HERE/'formal_functions.json').read_bytes())['functions']
    old = json.loads((HERE/'reused_functions.json').read_bytes())['functions']
    specs = [
        ('以627760根传6DB9D0取得0..100计数；连续文件加载，NULL回退系统箭头，再失败提示返回0；完成后初始化四缓存并返回1。',
         '配置记录生产者、首次/重载真实可达性、系统加载结果、句柄释放效果与保护诊断异常运行态未闭。',
         [('0x6bab97',['ecx']),('0x6bab9f',['ecx, eax']),('0x6babac',['byte ptr [eax], 1']),('0x6babb2',['byte ptr [ecx + 1], 0']),
          ('0x6babce',['jge']),('0x6babd8',['0xa23bcc']),('0x6babdd',['0x94']),('0x6babee',['0x10']),('0x6babf4',['2']),
          ('0x6babff',['0xad3f38']),('0x6bac12',['ecx*4 + 0xc']),('0x6bac21',['jne']),('0x6bac25',['0x7f00']),
          ('0x6bac2c',['0xad3f3c']),('0x6bac3f',['edx*4 + 0xc']),('0x6bac4e',['jne']),('0x6bac56',['0xa23be0']),
          ('0x6bac61',['0xad3f8c']),('0x6bac6e',['xor eax, eax']),('0x6bac80',['0x19c']),('0x6bac92',['0x1a4']),
          ('0x6bac9e',['0x10']),('0x6baca1',['0x1a0']),('0x6bacb3',['0x1a8']),('0x6bacc5',['0xad3f88']),
          ('0x6bacd2',['eax, 1']),('0x6bacda',['push eax']),('0x6bace6',['pop eax']),('0x6bad02',['ret'])]),
        ('扫Q=[this+3AC00]的100个12字节步长项，统计DWORD[Q+12C4+12*i]不等于FFFFFFFF的数量；无栈参数返回0..100。',
         'Q生产、记录全布局及非FFFFFFFF字段意义未闭；没有NULL/容量门，不由文件数推当前返回39。',
         [('0x6db9ee',['0']),('0x6db9f5',['0']),('0x6dba07',['0x64']),('0x6dba0b',['jge']),('0x6dba10',['0x3ac00']),
          ('0x6dba19',['0xc']),('0x6dba1c',['0x12c4','-1']),('0x6dba24',['je']),('0x6dba29',['ecx, 1']),('0x6dba31',['eax']),('0x6dba37',['ret'])]),
    ]
    old_anchors = [
        [('0x627790',['0xa766b0']),('0x627799',['0x99fe8']),('0x6277e0',['0xa766b0'])],
        [('0x627920',['0xa766c0']),('0x627929',['0x1ac']),('0x627970',['0xa766c0'])],
        [('0x6baace',['0x190']),('0x6baad3',['0']),('0x6baad8',['0xc'])],
        [('0x6bad9e',['ecx*4 + 0xc']),('0x6bada2',['je']),('0x6badb1',['0x19c']),('0x6badc4',['0x1a0']),('0x6badd6',['0xad3f88'])],
        [('0x6bab2a',['0x64']),('0x6bab2e',['jae']),('0x6bab36',['ecx*4 + 0xc']),('0x6bab4a',['0xad3acc'])],
        [('0x6298a1',['0x604627']),('0x6298a9',['1']),('0x6298b2',['0x604cfd']),('0x6298ca',['4'])],
        [('0x629ed3',['0xa76500']),('0x629ed9',['ret'])],
        [('0x91f6d0',['jne']),('0x91f6d2',['ret'])],
        [('0x9206dc',['0x10']),('0x92072d',['0x7fffffff']),('0x920789',['byte ptr [eax], 0']),('0x9207bd',['ret'])],
        [('0x91fbb0',['0xa69330']),('0x91fbb6',['jne']),('0x91fbb8',['ret'])],
    ]
    def record(row,index,file,status,conclusion,unknown,anchors):
        instructions = sum(x['is_code'] and x.get('normalized_item_kind')!='data' for x in row['normalized_assembly'])
        return dict(va=row['va'],status=status,conclusion=conclusion,unknown=unknown,source_path=row['source_path'],
                    source_pointer=row['source_pointer'],source_sha256=row['source_sha256'],declared_chunks=row['declared_chunks'],
                    evidence_ref=dict(file=file,pointer='/functions/'+str(index)),mechanical_instructions=instructions,
                    semantic_anchors=[dict(va=va,tokens=tokens) for va,tokens in anchors])
    functions = [record(row,i,'formal_functions.json','完整局部分析',*specs[i]) for i,row in enumerate(new)]
    historical = [record(row,i,'reused_functions.json','既有窄契约复用',row['adaptation_scope'],
                         '只复用正文所列身份、调用或正常路径；机械核全部源声明字节不表示异常及外部依赖业务闭合。',old_anchors[i])
                  for i,row in enumerate(old)]
    result = dict(disk_sha256=SHA,scope='两新本体局部契约；十历史记录另计，其中cookie仅正常三指令语义，旧声明填充不外推。',
                  functions=functions,historical_contracts=historical,
                  summary=dict(new_bodies=2,new_instructions=sum(x['mechanical_instructions'] for x in functions),
                               historical_records=10,historical_mechanical_instructions=sum(x['mechanical_instructions'] for x in historical),
                               explicit_owner_windows=1,direct_bridges=8),
                  owner_windows=[dict(owner_va='0x623cb0',site_va='0x623ced',status='局部窗口分析',
                                      evidence_ref=dict(file='bounded_raw.json',pointer='/explicit_owner_windows/0'),
                                      conclusion='取得鼠标根传入加载器；返回零则上跳启动失败返回路径。',unknown='整个启动流程与失败后清理不在本窗口覆盖。')])
    (HERE.parent/'函数审阅清单.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps(result['summary']))


if __name__ == '__main__':
    main()
