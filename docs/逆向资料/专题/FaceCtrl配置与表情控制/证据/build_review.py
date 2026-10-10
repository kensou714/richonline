"""生成逐函数审阅清单；范围保持原证字段，不把局部审阅抬升为全函数。"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent

CONCLUSIONS = {
    0x64CE50: ('已审阅', '8 字节对象构造仅清 +0，+4 未初始化。', '分配失败由外部单例处理。'),
    0x64CEC0: ('已审阅', '两遍 ITEM 计数和加载；108h 记录步长；8 字节别名槽无数量上界。', '分配、解析和解压依赖的全部错误语义未展开；仅发现启动调用。'),
    0x64D180: ('已审阅', 'strstr 最早字节偏移优先，同位置保持最早规则；以更新位 10h 向 4F 分发。', '文本编码及最终图像资源合同未确认；输入 NULL 后置检查。'),
    0x629160: ('已审阅', '调用64CE70释放记录数组，flags低位置位时再释放对象本体。', '删除器内部实现未审阅。'),
    0x64CE70: ('已审阅', '非空数组 delete[] 后清 +0，不清 +4。', '外部是否再次使用析构对象未知。'),
    0x6FC000: ('局部审阅', '工厂目标构造写 A27120 虚表；构造 +68h/21Ch/4 元素数组。', '基类和全部成员构造语义未展开；异常尾块保留但非全部语义解释。'),
    0x73A590: ('局部审阅', '更新位 10h 按首 DWORD 标识匹配四控件，提交 face 给 797800 并写 tick。', '其他更新位、797800 动画内部、刷新与到期合同未审阅。'),
    0x628FB0: ('复用局部审阅', 'A7673C 单例，申请8字节，构造64CE50。', '异常处理运行结果及并发保证未知。'),
    0x623EE0: ('复用局部审阅', 'FaceCtrl 路径和返回值启动检查。', '其他启动子系统未在本批审阅。'),
    0x6279C0: ('复用局部审阅', 'A766C8 管理器单例，申请6C0字节。', '管理器构造和其他界面合同未审阅。'),
    0x6E4640: ('复用局部审阅', '实例表84h步长，已存在实例调用虚表+10h；不创建。', '锁实现及其他槽位实例未审阅。'),
    0x64A9F0: ('复用局部审阅', '两个聊天现场调用FaceCtrl，传标识与文本，不消费返回EAX。', '整段聊天及文本前处理未全部审阅。'),
    0x8198E0: ('复用依赖审阅', 'LF终止复制，双字节和反引号n转换；写NUL后比较容量。', '畸形源串无终止时的运行行为未实机测试。'),
    0x81B4C0: ('复用依赖审阅', '二进制KPD读取并减首字节密钥，本调用零返回终止加载。', '共享读取器所有调用环境未审阅。'),
    0x819250: ('复用依赖审阅', 'mode2复制源串设置解析范围，flag0不变换。', '其他模式未在本批审阅。'),
    0x819470: ('复用依赖审阅', '精确ITEM节扫描，使用共享全局临时区。', '畸形节名内部边界与并发运行未测试。'),
    0x819660: ('复用依赖审阅', '当前节精确大小写键查询，保存值游标。', '缺失face后游标不构成默认值合同。'),
    0x81B7F0: ('复用依赖审阅', '解压输出，本FaceCtrl加载器不检查返回值。', '全部LZO错误返回及下游表现未展开。'),
    0x624080: ('复用局部审阅', '退出局部调用629160(flags1)并清A7673C。', '其他退出模块及线程同步未审阅。'),
    0x6E6080: ('复用局部审阅', '4F创建与销毁注册表目标定位。', '其他注册项及销毁6ECD70未审阅。'),
    0x6E3B40: ('复用局部审阅', '缺失实例按创建表生成，再使用界面虚调用。', '其他界面状态、参数及完整业务流程未审阅。'),
    0x6E8F50: ('复用主范围局部审阅', '工厂申请93Ch并经608745到6FC000。', '老证仅保存主范围；异常尾块未保存，不能宣称完整函数字节。'),
}


def build():
    rows = []
    for name in ('facectrl_raw.json', 'lifecycle_raw.json', 'consumer_constructor_raw.json', 'actual_consumer_raw.json'):
        data = (HERE / name).read_bytes()
        for record in json.loads(data)['functions']:
            rows.append((record, '证据/' + name, hashlib.sha256(data).hexdigest(), False))
    for row in json.loads((HERE / 'reused_evidence.json').read_bytes())['functions']:
        rows.append((row['record'], row['source'], row['source_sha256'], True))
    output = []
    for record, source, digest, reused in rows:
        va = int(record['va'], 16)
        status, conclusion, unknown = CONCLUSIONS[va]
        declared = record.get('declared_chunks', [])
        ranges = record.get('chunk_byte_ranges', []) or record.get('chunks', []) or record.get('byte_ranges', [])
        if not declared and record.get('chunks'):
            declared = [dict(start_va=r['va'], end_va=r['end_va'], is_main=r['va'] == record['va'])
                        for r in record['chunks']]
        output.append(dict(va=record['va'], status=status, conclusion=conclusion, unknown=unknown,
                           evidence=[dict(path=source, sha256=digest, entry=record['va'])],
                           reused=reused, original_byte_ranges=ranges, declared_chunks=declared,
                           range_limit=record.get('saved_scope', '原证已保存范围；范围完整不等于全部语义理解')))
    assert len(output) == len(CONCLUSIONS) == 22
    result = dict(schema=1, scope='7 个本批导出入口、15 个复用；分级按实际语义范围，不重复新增覆盖', functions=output,
                  followup=[dict(va='0x797800', reason='73B733实际消费face，内部字段与动画资源未展开'),
                            dict(va='0x6ecd70', reason='4F销毁注册目标尚未审阅')])
    (TOPIC / 'function_review.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(functions=len(output), fresh=7, reused=15)


if __name__ == '__main__':
    print(json.dumps(build(), ensure_ascii=False))
