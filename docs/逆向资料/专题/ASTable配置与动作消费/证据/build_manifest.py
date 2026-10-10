"""只按已审入口生成函数清单，派生块数据不改变审阅等级。"""
from pathlib import Path
from collections import Counter
import json

HERE = Path(__file__).resolve().parent

DETAILS = {
    0x627DB0: ('本地静态契约已审阅', 'A766F0懒单例分配32字节；保存构造返回，包含异常释放尾块。', '并发及异常运行库实现未在本专题全审。', '01_对象与加载边界.txt'),
    0x640100: ('本地静态契约已审阅', '只清四指针，不清四数量字段。', '分配器原内存内容未知。', '01_对象与加载边界.txt'),
    0x640230: ('本地静态契约已审阅', '依次加载DICE/MOVE/BACK/DENG；确定步长、键名和失败返回；未预检数量和必要键。', '共享助手、扩容和运行库异常后端未全部闭环。', '01_对象与加载边界.txt'),
    0x640B70: ('完整本体静态审阅', 'MOVE按prop首匹配返回记录指针；失败0。', '调用者缓存后绘制未在本专题追踪。', '03_访问器与真实消费.txt'),
    0x640BD0: ('完整本体静态审阅', 'BACK按prop首匹配返回记录指针；失败0。', '畸形数量/数组指针不受本地保护。', '03_访问器与真实消费.txt'),
    0x640C30: ('完整本体静态审阅', 'DENG按prop首匹配返回记录指针；失败0。', '畸形数量/数组指针不受本地保护。', '03_访问器与真实消费.txt'),
    0x7FB1C0: ('本地静态契约已审阅', '取this+9C低12位查DENG，直接取记录+8 anim；无空门。', '上游动作分派和结构消息身份未闭环。', '03_访问器与真实消费.txt'),
    0x646450: ('本地静态契约已审阅', 'DICE销毁回调，this+4交646720。', '析构异常后端未全审。', '02_记录布局与字段.txt'),
    0x646480: ('本地静态契约已审阅', 'DICE构造回调，this+4交6466C0。', 'allocator字段构造后端未全审。', '02_记录布局与字段.txt'),
    0x646750: ('部分审阅', '读size和capacity，unsigned比较后选择插入或扩容接口；loader传DWORD地址。', '646AC0/646860/6468A0插入扩容及异常后端未全审。', '02_记录布局与字段.txt'),
    0x7D7A90: ('完整本体静态审阅', '返回DWORD[this+9C]&0FFF，无calls。', '高位字段来源及所属对象完整结构未恢复。', '03_访问器与真实消费.txt'),
    0x629520: ('本地静态契约已审阅', '调用640140析构后按flags&1释放this，关闭局部以flags=1调用。', 'delete运行库实现未在本专题全审。', '01_对象与加载边界.txt'),
    0x6466C0: ('本地静态契约已审阅', '构造allocator接口后调用646B10，再以0调用646960。', 'allocator后端646B50未全审。', '02_记录布局与字段.txt'),
    0x646720: ('本地静态契约已审阅', '容器销毁包装，把this交646A20。', '容器释放的运行库异常语义未全审。', '02_记录布局与字段.txt'),
    0x646800: ('完整本体静态审阅', '首指针空则0，否则容量=(+0C-+04)>>2。', '损坏指针差的合法性无本地验证。', '02_记录布局与字段.txt'),
    0x640140: ('本地静态契约已审阅', '依次调用四数组销毁接口并清四指针；DICE传flags=3，四数量不清。', '6463B0数组展开与91F7E0释放后端未全审。', '01_对象与加载边界.txt'),
    0x646B10: ('部分审阅', '把栈参数地址交612461到6470C0后返回this；本体无字段写入。', '6470C0后端及allocator真实字段内容未全审。', '02_记录布局与字段.txt'),
    0x646A20: ('部分审阅', 'begin非空时交begin/end给646BA0，交begin/capacity给6470E0；最后清三指针。', '646BA0/6470E0区间处理、释放与异常后端未全审。', '02_记录布局与字段.txt'),
    0x646960: ('既有原证本地复核', '先清三指针，参数0时AL=0返回；非零分配路径写begin/end/cap。', '上限、分配和失败后端未全审，不能认领源码真实类名。', '02_记录布局与字段.txt'),
}


def main():
    result = []
    for source in ('functions_raw.json', 'closure_raw.json', 'lifetime_raw.json', 'fields_raw.json', 'fields_reused.json'):
        data = json.loads((HERE / source).read_text('utf-8'))
        for function in data['functions']:
            address = int(function['va'], 16)
            status, conclusion, unknown, document = DETAILS[address]
            result.append(dict(va=hex(address), end_va=function['end_va'], status=status,
                               conclusion=conclusion, unknown=unknown, document=document,
                               evidence=['证据/' + source], evidence_pointer='/functions/' + str(data['functions'].index(function)),
                               chunks=function['chunk_byte_ranges'], instructions=len(function['assembly']),
                               review_scope='完整本体与声明尾块已逐指令读取；外部依赖以unknown限制闭环'))
    result.extend([
        dict(va='0x642740', status='历史原证局部复用', conclusion='642921..6429E4审三种配置键变化和缓存去向。',
             unknown='其余精灵初始化/绘制不在本专题认领。', document='03_访问器与真实消费.txt',
             evidence=['证据/consumer_reused.json'], review_scope='仅消费者局部；完整块匹配不是整函数新增审阅'),
        dict(va='0x63f870', status='既有完整契约复用', conclusion='首指针空则0，否则size=(+08-+04)>>2。',
             unknown='容器其他算法不因本条变成已审。', document='02_记录布局与字段.txt',
             evidence=['证据/size_reused.json'], review_scope='复用角色与精灵动画已审计数函数；不重计新完成量')
    ])
    output = dict(schema=1, pe_sha256=data['disk_sha256'], scope='ASTable：逐函数本地契约与有限生命周期；外部后端不计闭环',
                  status_counts=dict(Counter(item['status'] for item in result)), functions=result)
    (HERE.parent / '函数审阅清单.json').write_text(json.dumps(output, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    lines = ['// ============================================================================', '// ASTable / 逐函数结论', '// ============================================================================']
    for item in result:
        lines.extend(['//', '// ' + item['va'].upper() + ' / ' + item['status'], '//   ' + item['conclusion'], '//   未知：' + item['unknown']])
    (HERE.parent / '06_逐函数结论.txt').write_text('\n'.join(lines) + '\n', 'utf-8')
    print(json.dumps(dict(functions=len(result), status_counts=output['status_counts']), ensure_ascii=False))


if __name__ == '__main__':
    main()
