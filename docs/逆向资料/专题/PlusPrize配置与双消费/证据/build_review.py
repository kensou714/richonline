"""逐函数记录本专题实际审阅等级和未知，不把外部依赖扩大为整体完成。"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
NOTES = {
 0x7FDE40: ('已审阅','读取SETUP四键：byte enable和三个atoi DWORD；文件打开失败不写对象。','缺节/键无默认保护；畸形解析和解压错误未实测。'),
 0x727A50: ('已审阅','返回this首BYTE；PlusPrize调用现场为enable。','通用同代码模式不独占PlusPrize类型。'),
 0x7D7EB0: ('已审阅','返回this+4 DWORD；本消费取card。','其他对象使用同函数的语义未知。'),
 0x7D7F00: ('已审阅','返回this+C DWORD；本消费取bout。','其他对象使用同函数的语义未知。'),
 0x727E00: ('已审阅','道具对象记录步长1128、+28 double，无索引检查。','输入合法范围、记录分配和量值单位未在本批审阅。'),
 0x7D02B0: ('已审阅','独立once缓存enable/card；道具double转float乘有符号card累加+5BC槽；无有效浮点返回合同。','两索引边界、外部缓存重置和累计单位未知。'),
 0x7D03C0: ('已审阅','独立缓存enable/bout，n阈值归一后按两BYTE谓词汇总+59C和+5BC到+5FC并返回float。','外部状态检查含义、数组容量和总值业务单位未知。'),
 0x7D6550: ('已审阅','返回this首DWORD；本消费传父对象+C44，按有符号n作bout归一分子。','其字段生产、单位和更大对象业务角色未审阅。'),
 0x7D7ED0: ('已审阅','返回this+E48+idx BYTE，本消费要求为零；无索引检查。','该BYTE的业务含义、生产和合法索引域未审阅。'),
 0x628D20: ('复用已审阅','A76708单例申请16字节，不调用构造、不初始化字段。','分配失败和并发使用未知。'),
 0x623EE0: ('复用局部审阅','PlusPrize加载返回零使启动失败。','其他启动子系统未在本专题审阅。'),
 0x624080: ('复用局部审阅','PlusPrize退出直接delete后清全局。','其他退出流程未整体审阅。'),
 0x627C20: ('复用局部审阅','A766E0道具单例，727E00调用域不同于PlusPrize。','道具对象构造与全记录布局未审阅。'),
 0x691A70: ('复用局部审阅','读取this+18并转交外部检测，本消费使用低BYTE。','外部检测业务状态未知。'),
 0x64EFA0: ('复用已审阅','返回this+E38+idx BYTE，本体无索引检查。','状态生产和合法索引域未知。'),
 0x819250: ('复用依赖审阅','mode2复制解析数据并设置范围，PlusPrize flag0。','其他模式未审阅。'),
 0x819470: ('复用依赖审阅','大小写精确查SETUP并更新游标；失败不产生默认集合。','畸形内层扫描及线程安全未实测。'),
 0x819660: ('复用依赖审阅','精确键查询，失败游标不能当作缺键默认值。','畸形键扫描运行结果未知。'),
 0x8198E0: ('复用依赖审阅','LF终止复制，写NUL后检查容量128；不是安全截断。','无终止源及超长值未实测。'),
 0x81B4C0: ('复用依赖审阅','KPD读取，零返回进入PlusPrize失败分支。','短读和全部共享调用环境未知。'),
 0x81B7F0: ('复用依赖审阅','解压输出；PlusPrize不检查返回。','全部解压错误状态未展开。'),
}


def build():
    records=[]
    for name in ('plusprize_raw.json','consumer_helpers.json'):
        raw=(HERE/name).read_bytes()
        for record in json.loads(raw)['functions']:
            records.append((record,'证据/'+name,hashlib.sha256(raw).hexdigest(),False))
    for row in json.loads((HERE/'reused_evidence.json').read_bytes())['functions']:
        records.append((row['record'],row['source'],row['source_sha256'],True))
    rows=[]
    for record,source,sha,reused in records:
        status,conclusion,unknown=NOTES[int(record['va'],16)]
        chunks=record.get('declared_chunks',[])
        if not chunks:
            chunks=[dict(start_va=r['va'],end_va=r['end_va'],is_main=r['va']==record['va']) for r in record.get('chunks',[])]
        rows.append(dict(va=record['va'],status=status,conclusion=conclusion,unknown=unknown,reused=reused,
                         evidence=[dict(path=source,sha256=sha,entry=record['va'])],declared_chunks=chunks,
                         original_byte_ranges=record.get('chunk_byte_ranges',[]) or record.get('chunks',[]) or record.get('byte_ranges',[])))
    assert len(rows)==21
    result=dict(scope='9当前导出与12复用；外部依赖业务未知与字节完整性分开',functions=rows,
                followup=['PlusPrize+8 avatar访问器与消费者','两once缓存外部重置现场','双消费槽数量和索引生产'])
    (HERE.parent/'function_review.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return dict(functions=len(rows),fresh=9,reused=12)


if __name__=='__main__':
    print(json.dumps(build(),ensure_ascii=False))
