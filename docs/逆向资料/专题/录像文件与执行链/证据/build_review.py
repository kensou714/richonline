"""保留每个候选的人工分析等级；数量不自动升级为语义覆盖。"""
import hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent;TOP=HERE.parent
GROUPS=['startup_and_navigation.json','io_and_parser_navigation.json',
        'controls_and_flow_navigation.json','controls_and_queue_navigation.json',
        'queue_and_ui_gate.json','replay_state_stubs.json','digest_helper.json']
NOTES={}
def note(level,summary,*addresses):
    for address in addresses:NOTES[hex(address)]=(level,summary)
note('完整窄函数核验','完整函数仅返回1；不恢复历史状态名称。',0x6258F0,0x625900)
note('完整窄函数核验','主状态读写或启动选择值小型辅助。',0x629DC0,0x62A0F0,0x627020,0x627050,0x627060)
note('完整窄函数核验','包装调用KetMd5GetDigest，目标827B30，非录像专属实现。',0x81B980)
note('完整窄函数核验','取得UI0并通过虚表+100/+120派发；只定义包装层契约。',0x6EE900,0x6EEA90)
note('完整窄函数核验','UI116只处理命令2重命名、3删除；无1播放分支。',0x761D50)
note('局部分支核验','录像控件注册、文案与初始化后隐藏150；其余游戏UI未逐条分析。',0x7045A0)
note('局部分支核验','F11状态2/13选择控件150/151/160/161并调虚表+120。',0x705C70)
note('局部分支核验','四个录像编号均落默认分支；其余命令业务未逐条分析。',0x7061F0)
note('局部分支核验','主状态间接表与索引12/13目标；其他主循环行为不扩展。',0x624CA0)
note('局部分支核验','清理、状态归零与UI切换；未解释所有子调用。',0x625910)
note('局部分支核验','pack与run_分支、RichTool启动、参数移交。',0x7A3D90,0x7A3BB0)
note('局部分支核验','首参数路径及第二参数atoi，区域选择标志；不声称健全命令行解析。',0x622E20)
note('局部分支核验','[AREA]/num及AREA%d区域配置字段与3452B行；不解释所有KPD辅助。',0x623030)
note('局部分支核验','加载后的UI65/UI66及区域选择路径。',0x625310)
note('局部分支核验','每帧隐藏控件4/400；其他UI帧动作只导航。',0x7526F0)
note('局部分支核验','命令4保留显示面板，行410..520打开UI116；其余设置只导航。',0x752A00)
note('局部分支核验','接收数据处理成功后调用64F870并刷新时间；未恢复传输解析器。',0x6BEE80)
note('局部分支核验','特殊事件分流与默认入队；各特殊处理器另专题。',0x64F870)
note('局部分支核验','本地事件包装至插入队列；短记录尾部不是磁盘帧。',0x64FA50)
note('局部分支核验','288B容器复制和位置/计数变更；反编译参数失真，ABI未发布。',0x698050,0x6980F0)
note('局部分支核验','使用相同接收包装函数的另一调用者；不能把每个调用等同网络。',0x7CF630)
note('局部分支核验','消费门控、288B出队与分派；全部事件语义并非本专题覆盖。',0x7BB290)
note('复用契约并补验','向量初始化、分页或队列取出/门控；完整基础说明见已有专题。',0x751BD0,0x701D60,0x7D7F20,0x7D8010,0x64FB70)
note('局部用途核验','重命名拼接.rcd并MoveFile；未解析正文。',0x762060)
note('局部用途核验','Voice.dat角色语音参数读写路径。',0x69AAA0,0x69ABE0)
note('局部用途核验','Item%s.tb、Pack%s.npp资源读取与定位。',0x6DA7B0,0x6DBE30)
note('局部用途核验','地图加载/预览/摘要/描述/ITEM读取，非RCD格式证据。',0x7DF010,0x7E6F10,0x7E71E0,0x7E72A0,0x7E8EB0)
note('局部用途核验','通用全文/文本加载或下载封装，不确认录像用途。',0x81AE00,0x81E580,0x81E290)
note('局部用途核验','通用KPD编解码。FILE*写出调用来源未闭合，不推录像。',0x81B150,0x81B310,0x81B4C0,0x81B670)
note('局部用途核验','Private.tmp/Private.kpd写出调用；其余UI动作不扩大覆盖。',0x70F9E0,0x738F60)
note('局部用途核验','User.kpd路径设置或128B账户区写出；其余登录动作不扩大覆盖。',0x72A080,0x72B910)
note('局部用途核验','文本日志目录、追加或刷新；仅相关I/O分支。',0x623AD0,0x81BEA0,0x81C190,0x81C2B0)
note('局部用途核验','资源包索引读/定位，未恢复本专题外的所有库契约。',0x81FAC0,0x81FC50,0x8247D0,0x824960,0x825230)
note('局部用途核验','文件MD5按4096B读取，不确认记录业务归属。',0x827B30)
note('局部用途核验','按[section]和key=value生成文本；上层业务只导航。',0x9109D0)
records={}
for name in GROUPS:
    group=json.loads((HERE/name).read_text(encoding='utf-8'))
    for function in group['functions']:
        va=function['va']
        level,summary=NOTES.get(va,('仅导出候选','仅作交叉引用/I/O导航；没有人工语义完成声明。'))
        if va not in records:
            records[va]=dict(va=va,name=function['name'],level=level,summary=summary,
                             status=level,conclusion=summary,
                             unknown='仅作导航，未恢复业务语义；所有动态路径均未验证。' if level=='仅导出候选' else
                                     '仅覆盖本项结论及正文指定范围；外部依赖全闭环、其他分支与动态可达性未验证。',
                             evidence=[],full_dependency_closure=False,
                             declared_chunks=function['declared_chunks'],sources=[])
        records[va]['sources'].append('证据/'+name)
        records[va]['evidence'].append('证据/'+name)
unknown=set(NOTES)-set(records)
assert not unknown,unknown
windows=[dict(start_va=x['start_va'],end_va=x['end_va'],
              level='局部窗口核验' if int(x['start_va'],16) in (0x7DEDC0,0x81B8B0) else '仅导航窗口',
              summary='人工划定窗口不等于IDA函数；正文中的局部步骤以03为准。')
         for x in json.loads((HERE/'undeclared_io_windows.json').read_text(encoding='utf-8'))]
result=dict(provenance='本代理编写查询；父代理在其IDA-MCP只读lease执行；本代理从当前PE及资源独立重验。',
            function_count=len(records),functions=sorted(records.values(),key=lambda x:int(x['va'],16)),
            raw_windows=windows,script_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted(HERE.glob('*.py')) if p.name not in ('validate.py',)})
(TOP/'function_review.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(dict(functions=len(records),levels={level:sum(x['level']==level for x in records.values())
                   for level in sorted({x['level'] for x in records.values()})}),ensure_ascii=False))
