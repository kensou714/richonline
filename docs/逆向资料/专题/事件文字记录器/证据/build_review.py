"""逐函数人工结论与部分审阅状态；机械提取仅用于核对已审阅的事件模板。"""
from pathlib import Path
from collections import Counter
import json
import re

BASE = Path(__file__).resolve().parent
SOURCES = ['core.json','lifecycle.json','buffers.json','record_writers.json','event_producers.json',
           'cleanup_and_encoding.json','resource_parser.json','shutdown.json','shutdown_bridge.json','date.json']
NOTES = {
'6271b0':'ABABC4单例getter；分配44字节，调用输出器构造81BD80。',
'7dccc0':'LogFixStr装载：size/count/STRING indx/win32，loaded=1后发事件0；未校验索引与分配乘积。',
'7dcfe0':'65个有输出事件：0..63走Sys，128走Game；sprintf写this起点，非空再输出。',
'7de2d0':'固定文本getter：DWORD[this+260]+index*DWORD[this+264]，无索引边界检查。',
'81c190':'channel0/+12与channel1/+28缓冲；门限或force触发fwrite后清used，FILE空也清。',
'623ad0':'启动局部：加载ChsTb，取得输出单例并以1024初始化门限；其余平台初始化未闭合。',
'623b60':'启动局部：Role资源成功后以Data/LogFixStr.kpd装载格式器；外围图形/声音依赖未闭合。',
'7dcbe0':'276字节格式器构造仅清+260表指针和+272 loaded。',
'7dcc10':'先构造12字节事件1并格式化，然后释放+260固定文本表并清指针。',
'81bd80':'44字节输出器构造：+12/+28缓冲构造，+0/+4 FILE指针清0。',
'81be00':'输出器析构：先补写两路缓冲，fclose两个非空FILE，再释放两缓冲。',
'81bea0':'按日期创建Log/Game及Log/Sys子目录，以at打开game.txt/sys.txt，配置门限与512增长块。',
'81c2b0':'补写两个非空FILE的非空缓冲；不清used，不能视为可反复调用的写后清空接口。',
'627380':'A766AC单例getter，分配276字节并调用7DCBE0构造。',
'81d6e0':'缓冲reset仅把this+0 used清0。',
'81d710':'16字节缓冲构造只清this+12 data。',
'81d730':'缓冲析构转交81D7C0清理。',
'81d760':'缓冲初始化：used0、capacity参数、growth参数、分配data；当前调用容量1024增长512。',
'81d7c0':'非空data调用delete后置0；不重写used/capacity/growth。',
'81d810':'追加原始字节；空间不足按growth块扩容并复制旧capacity字节，返回新数据起点。',
'9243e0':'锁定FILE后调用fwrite再解锁，返回fwrite结果；上层不检查返回值。',
'627160':'字符转换对象单例ABABB8；仅分配0x18968字节，初始化在其它路径。',
'62a0f0':'返回全局A6723C DWORD；649A30用其<12作为原文写日志的资格门，未在此命名业务枚举。',
'629a20':'格式器删除包装：先7DCC10析构，flag低位1时释放对象。',
'64f000':'读取字符转换对象+100708 DWORD，等于1表示启用本次映射分支。',
'818f10':'双字节范围谓词：A140..A3FE、A440..C67E或C940..F9FE。',
'8190b0':'原地双字节转换：高位字符且范围命中时按对象映射表替换；映射初始化未闭合。',
'81db00':'输出器删除包装：81BE00析构后按flag低位释放对象。',
'8191d0':'文本解析器构造清流/数据/三游标，非整对象清零。',
'819220':'文本解析器析构转交8193F0。',
'819250':'解析器mode1读文件、mode2复制内存，保存长度与游标；本组mode2且转换标志0。',
'8193f0':'清流及游标，释放解析器复制的数据块。',
'819470':'找节标记：跳//整行，比较方括号内容；本组ALL/STRING。',
'819660':'从当前节起点找键，跳空白与注释，见下一节终止；等号后跳前导空白但保留LF。',
'8198e0':'行复制：高位双字节原样、反引号+n转LF；写NUL后才断言count+1不超过容量。',
'81ad50':'KPD临时对象析构转交81AD80释放解包及压缩块。',
'81ad80':'分别释放this+0解压块与this+4压缩块，并置0。',
'81b4c0':'KPD读文件、key反变换及压缩数据装入；fread长度返回未核，成功打开即沿此路径返回1。',
'81b7f0':'分配解压内存并调用KetLzoDecompress，算法及失败传播仅记录调用边界。',
'624080':'总关闭局部：释放A766AC格式器后经623B40到通用清理；其它子系统析构仅保留原证。',
'81d6a0':'缓冲data getter：返回this+12 DWORD。',
'81d6c0':'缓冲used getter：返回this+0 DWORD。',
'81d9b0':'通用单例清理：ABABC4经81DB00销毁并清0；其他单例仅保存外围证据。',
'623b40':'退出桥接经61280D跳板到81D9B0。',
'62a0a0':'日期单例ABABC0：首次分配40字节，不在getter中初始化tm。',
'81bc30':'当前time写this+0；localtime结果36字节tm复制到this+4，作为文件目录日期来源。',
'629fc0':'日期年getter：tm_year(this+24)+1900。',
'629ff0':'日期月getter：tm_mon(this+20)+1。',
'62a020':'日期日getter：返回tm_mday(this+16)。',
}
PARTIAL = {'623ad0','623b60','624080','627160','8190b0','81b7f0','81d9b0'}
functions = []
producer_map = []
for source in SOURCES:
    for f in json.loads((BASE/source).read_text('utf-8'))['functions']:
        key=f['va'][2:]
        pseudo='\n'.join(f['pseudocode']) if isinstance(f['pseudocode'],list) else f['pseudocode']
        if source=='record_writers.json':
            field=0 if key=='64f1a0' else 4
            assert ('*this = a2;' if field==0 else '*(this + 1) = a2;') in pseudo
            note='本地记录+%d DWORD写入器；只赋传入参数，不清其它字段，原MFC名称不作语义。'%field
        elif source=='event_producers.json':
            event=int(re.search(r'j_unknown_libname_345\(a1: (\d+)\)',pseudo)[1])
            ids=[int(i) for i in re.findall(r'sub_60FC52\(a1: (\d+)\)',pseudo)]
            producer_map.append(dict(va=f['va'],event=event,ui_resource_ids=ids,force=0,
                                     scope='日志调用链已审阅；外围UI业务未闭合'))
            if event==128:
                note=('300像素分行界面文字，A6723C<12时原文送128；' if key=='649a30' else
                      '430像素分行界面文字、512项门后送128；')+'12字节记录+4为原输入字符串。'
            else:
                note='事件%d生产者：把输入a2写记录+4并force0送Sys；UI文本索引%s，外围业务部分分析。'%(event,','.join(map(str,ids)))
            PARTIAL.add(key)
        else:
            note=NOTES[key]
        functions.append(dict(va=f['va'],sources=[source],review_status='部分分析' if key in PARTIAL else '局部语义已审阅',
                              conclusion=note,unknown='外部依赖及动态运行未完整闭合。'))
assert len(functions)==len({f['va'] for f in functions})
result=dict(sources=SOURCES,counts=dict(Counter(f['review_status'] for f in functions)),
            functions=sorted(functions,key=lambda f:int(f['va'],16)),producer_map=producer_map)
(BASE/'function_review.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
lines=['// 逐函数审阅清单','//','// “局部语义已审阅”只确认该函数职责；不表示整个调用闭包或运行行为已验证。','//']
for f in result['functions']:
    lines.extend(['// '+f['va'].upper()+'  '+f['review_status'],'//   '+f['conclusion']])
(BASE.parent/'05_逐函数审阅.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8')
print(json.dumps(dict(functions=len(functions),counts=result['counts']),ensure_ascii=True))
