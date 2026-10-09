"""复核本专题字节、ABI断言与资源指纹，生成局部审阅清单；不修改全局统计。"""
import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[3]
EVIDENCE = HERE / '证据'
FILES = ('handlers.json', 'helpers.json', 'consumers.json', 'ui_and_property.json',
         'wait_window.json', 'adjacent_wait_context.json', 'wait_phase_and_owner_effect.json',
         'resource_loader_scope.json', 'text_recording.json')
CONCLUSIONS = {
    0x65E310: ('4019以signed WORD角色槽取得P，复制packet+6的24字节到P+1520。', '不证明八槽全量同步、UI刷新或网络回执。'),
    0x65E380: ('401A核验身份、主状态!=12及分类字节0后，向UI77传{1,显示序号,角色槽}。', '角色合法域、对象尚未创建时的补通知策略未知。'),
    0x65E680: ('401D以signed BYTE新/旧业主转移全图归属，按旧/新角色名格式化RichStr328并写提示。', '服务端资金结算与后续阶段消息需日志验证。'),
    0x7EF9D0: ('4019桥接以ECX传G，压入packet调用65E310。', '上游帧长度保证不在桥接函数。'),
    0x7EF9F0: ('401A桥接以ECX传G，压入packet调用65E380。', '上游角色槽合法性不在桥接函数。'),
    0x7EFA50: ('401D桥接以ECX传G，压入packet调用65E680。', '上游new/old合法域不在桥接函数。'),
    0x7F46F0: ('memcpy(P+1520,Src,0x18)，仅覆盖24字节。', '四槽区段同步的历史协议设计意图未知。'),
    0x7F86A0: ('group0/1/2分别从P+1520/+282/+330按6字节取signed WORD ID。', '本批只用于证明4019写入区段布局。'),
    0x7F8780: ('group0插入循环上界8、步长6字节，作为4019长度比较证据。', '合成与UI依赖沿用4050及商店专题，不在本批重复完成。'),
    0x62A0F0: ('返回全局主状态A6723C。', '全部主状态业务不在本专题。'),
    0x63F390: ('返回BYTE[G+3672+slot]分类值。', '分类字节完整命名和值域未恢复。'),
    0x64FD40: ('非模式3原样返回槽；模式3只统计分类0槽得到压缩序号。', '非法槽未命中会返回最终数量，调用者约束未闭环。'),
    0x64FDE0: ('分类非0槽从显示序号4开始计数并映射目标槽。', '不能据起点4推定所有模式人数上限。'),
    0x63E160: ('读取this+24并转63E1A0比较模式3。', 'this在G或M调用点分别核对，不能合并对象布局。'),
    0x63E1A0: ('返回传入模式是否等于3。', '正式模式名称以其他专题为准。'),
    0x6279C0: ('取得UI管理器单例，首次分配0x6C0并构造。', '构造所有成员及错误路径未在本批展开。'),
    0x6E4640: ('临界区内查132字节UI槽+4对象，存在才调用虚表+10传载荷。', '不创建缺失UI对象；间接消费者按具体槽核验。'),
    0x6E8E30: ('UI77工厂分配0x48并转6FBF80构造。', '内存分配失败时上层处理未实测。'),
    0x6FBF80: ('经基类构造后设置UI77虚表A26F80。', '基类字段完整初始化沿用界面专题。'),
    0x739410: ('窗口初始化取分类10子类24提示图，更新配置序号，并隐藏控件20..24。', 'N=0取模及缺失控件的运行时表现未知。'),
    0x739500: ('载荷0显示服务端完成，载荷1按显示序号和角色名更新标签；不发送网络回执。', '其他载荷首值、非法序号及全局G与入口G不一致时未验证。'),
    0x6DB960: ('统计图像分类10的子类24共100槽中句柄非-1项。', '返回数量不证明所有非空项连续。'),
    0x797780: ('读取配置对象DWORD+84提示图序号。', '配置载入和持久化边界未展开。'),
    0x7977A0: ('写配置对象DWORD+84提示图序号。', '配置保存节拍不在本函数。'),
    0x6FA7F0: ('把图像句柄交8E1C70，目的为控件+164图像字段。', '具体绘制帧推进与贴图成功沿用图像专题。'),
    0x629C90: ('取得游戏对象单例，首次分配0x14794。', '对象建立完整时序及空返回未展开。'),
    0x63E230: ('从G+0xE00按DWORD角色槽返回P。', '没有角色槽边界或空指针检查。'),
    0x63E1C0: ('返回this+112字符指针；本次this=P用于角色名。', '角色名容量、编码和终止保证未在本批恢复。'),
    0x6E3B40: ('局部核对UI对象创建、虚表+8初始化和显示，打开UI77由6AB6D0调用。', '其他UI槽、失败回滚与所有依赖不在本批完成范围。'),
    0x6E4020: ('局部核对UI关闭、移出活跃容器及延后释放pending标志。', '不是网络pending，完整prev/dvs链沿用界面专题。'),
    0x6ECC90: ('UI77释放工厂调用6FF110并清槽对象指针。', 'free策略调度与释放时刻沿用界面专题。'),
    0x6FF110: ('调用6FF160析构，参数位0决定是否delete对象。', '基类底层资源释放沿用界面专题。'),
    0x6FF160: ('转入基类6E1DD0析构。', '未递归审阅基类所有成员。'),
    0x6AB6D0: ('只审阅连接成功分支切主状态1并打开UI77。', '网络重试、事件6及完整游戏准备链不计本批完成。'),
    0x65D520: ('4010的+6==0且原主状态1分支切2、关UI77并进入7C0C50阶段链。', '非零+6分支和完整回合阶段由既有专题维护。'),
    0x65E460: ('401B写G内160字节角色区段及G+1500数组，不关闭UI77。', '仅作相邻编号排除证据，不提升完整401B业务完成度。'),
    0x7E3B80: ('遍历M+36总格数，旧owner匹配时依次解除旧归属、写新归属。', '合法业主域和old=-1的上层约束未知。'),
    0x7E3E60: ('kind12种类2时条件清特殊表；随后owner=-1、重取中立地块图，种类10再刷新建筑图。', '特殊表的官方业务名称和值域未恢复。'),
    0x7E3C00: ('写owner并按模式3分类映射重取地块图，种类10刷新建筑图。', '图像句柄-1的绘制表现未实测。'),
    0x63E2D0: ('判断地图地产记录首signed BYTE kind==12。', '其他kind含义不在本函数。'),
    0x692940: ('判断地产记录+1建筑种类==2。', '种类2对应特殊表的完整业务未恢复。'),
    0x7E4B10: ('查M+304六字节表中格号和owner是否同时匹配。', '表生命周期与其余字节含义未知。'),
    0x7E4F60: ('查对应格号/owner并只将匹配记录首WORD设-1。', '不清其余字节，重复匹配项策略未知。'),
    0x63EBC0: ('判断地产记录建筑种类==10。', '资源名碉堡只引用当前build.dat，不扩大到其他枚举。'),
    0x7E73F0: ('kind11/12按等级取建筑图；种类10按owner有无取0/1变体。', '其余kind跳过，资源加载和显示成功需运行时验证。'),
    0x6DBA40: ('局部核对分类2/3/10的运行时图像槽查询和边界。', '其他分类及所有图像装载路径不计完成。'),
    0x6D8130: ('局部核对event.dat/build.dat/other.dat写入分类2/3/10映射数组。', '大型加载器只审阅关联区段；完整函数及错误路径未完成。'),
    0x627B60: ('取得12字节文本表单例。', '文本表装载细节不在本批。'),
    0x6D7170: ('文本表构造只清this+8指针。', '条目步长和容量由后续装载建立。'),
    0x629D90: ('返回表基址this+8所指加条目步长*this与编号的乘积。', '该函数无编号边界检查，运行表尺寸尚未补证。'),
    0x62A100: ('取得0x1688字节提示对象单例。', '构造内部缓冲容量不在本批完整展开。'),
    0x649A30: ('文字按像素宽度分段到340字节环形记录，主状态<12时另交事件128文字记录。', '完整字体宽度、颜色解释及最终绘制消费者未闭环。'),
    0x649F60: ('环形写下标递增取模，容量满时推进旧记录起点。', '容量为零或非法计数的上层保证未知。'),
    0x64F1A0: ('写载荷首DWORD，调用649A30时为128。', '其他事件载荷不在本批。'),
    0x64F1D0: ('写载荷第二DWORD，调用649A30时为文字指针。', '异步保存保证需结合记录消费者。'),
    0x7DCFE0: ('只审阅事件128分支：格式化文字加换行后交81C190记录入口。', '其他事件分支、日志落盘格式和录像关系不计本批完成。'),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    blob = (PROJECT / 'RnClient.exe').read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    require(blob[pe:pe+4] == b'PE\0\0', '不是PE文件')
    count = struct.unpack_from('<H', blob, pe + 6)[0]
    optional = struct.unpack_from('<H', blob, pe + 20)[0]
    require(struct.unpack_from('<H', blob, pe + 24)[0] == 0x10B, '要求PE32样本')
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    sections_pe = []
    for index in range(count):
        at = pe + 24 + optional + index * 40
        _, rva, size, raw = struct.unpack_from('<IIII', blob, at + 8)
        sections_pe.append((rva, size, raw))

    def disk(va, size):
        for rva, raw_size, raw in sections_pe:
            relative = va - base - rva
            if 0 <= relative and relative + size <= raw_size:
                require(raw + relative + size <= len(blob), 'PE原始数据越界')
                return blob[raw + relative:raw + relative + size]
        raise ValueError('无PE原始映射：' + hex(va))

    def check(item):
        value = disk(int(item['va'], 16), item['size'])
        require(value.hex() == item['disk_hex'] == item['idb_hex'], '字节不匹配：' + item['va'])
        if 'target' in item:
            require(len(value) == 5 and value[0] == 0xE9, '并非E9跳板：' + item['va'])
            target = int(item['va'], 16) + 5 + struct.unpack_from('<i', value, 1)[0]
            require(target == int(item['target'], 16), '跳板目标不符：' + item['va'])

    functions, thunks, review = {}, {}, []
    instruction_count = 0
    instruction_bytes = 0
    for filename in FILES:
        data = json.loads((EVIDENCE / filename).read_text(encoding='utf-8'))
        require(data['disk_sha256'] == digest, '版本指纹不同：' + filename)
        for function in data['functions']:
            va = int(function['va'], 16)
            require(va not in functions and va in CONCLUSIONS, '重复或未显式审阅：' + function['va'])
            functions[va] = function
            declared = [(int(c['start_va'], 16), int(c['end_va'], 16))
                        for c in function['declared_chunks']]
            for start, end in declared:
                require(any(start <= int(i['va'], 16) < end for i in function['assembly']),
                        '函数块没有保存指令：' + hex(start))
            for chunk in function['byte_ranges']:
                check(chunk)
                instruction_bytes += chunk['size']
            for instruction in function['assembly']:
                address = int(instruction['va'], 16)
                require(any(start <= address and address + instruction['size'] <= end
                            for start, end in declared), '指令不在声明函数块')
                require(any(int(chunk['va'], 16) <= address and
                            address + instruction['size'] <= int(chunk['va'], 16) + chunk['size']
                            for chunk in function['byte_ranges']), '指令不在已核验范围')
                instruction_count += 1
            conclusion, unknown = CONCLUSIONS[va]
            review.append({'va': function['va'], 'status': '静态局部语义已审阅',
                           'conclusion': conclusion, 'unknown': unknown,
                           'evidence': f'证据/{filename}/functions/{function["va"]}'})
        for thunk in data['thunks']:
            check(thunk)
            if thunk['va'] in thunks:
                require(thunks[thunk['va']] == thunk, '同跳板原证冲突')
            thunks[thunk['va']] = thunk
    require(set(functions) == set(CONCLUSIONS), '显式结论与原证地址不一致')
    recheck = json.loads((EVIDENCE / 'ida_recheck.json').read_text(encoding='utf-8'))
    require(recheck['disk_sha256'] == digest, 'IDA复核版本不同')
    checked = {}
    for item in recheck['files']:
        require(not item['mismatches'], 'IDA复核存在不匹配')
        for entry in item['function_chunks']:
            checked[int(entry['va'], 16)] = entry
    require(set(checked) == set(functions), 'IDA复核函数集合不同')
    for va, function in functions.items():
        entry = checked[va]
        require(entry['declared_chunks'] == function['declared_chunks'] and
                entry['instruction_count'] == len(function['assembly']) and
                entry['instruction_bytes'] == sum(i['size'] for i in function['assembly']),
                'IDA复核函数块或指令统计不同：' + hex(va))

    # ABI断言依托导出指令文本，且对应机器字节已和当前磁盘逐字节核对。
    def text_at(function, address, fragment):
        row = next(row for row in functions[function]['assembly'] if int(row['va'], 16) == address)
        require(fragment in row['text'], 'ABI断言不匹配：' + hex(address))

    text_at(0x65E310, 0x65E350, 'movsx')
    text_at(0x65E310, 0x65E357, '[ecx+eax*4+0E00h]')
    require(any('push    18h' in row['text'] for row in functions[0x7F46F0]['assembly']), '24字节复制断言失败')
    text_at(0x65E680, 0x65E6CE, 'movsx')
    text_at(0x65E680, 0x65E6D6, 'movsx')
    text_at(0x65E680, 0x65E6DE, '65Ch')

    vtable = json.loads((EVIDENCE / 'ui77_vtable.json').read_text(encoding='utf-8'))
    require(vtable['disk_sha256'] == digest, '虚表版本指纹不同')
    for chunk in vtable['byte_ranges']:
        check(chunk)
    for entry in vtable['entries']:
        address = int(vtable['table_va'], 16) + int(entry['slot'], 16)
        pointer = struct.unpack('<I', disk(address, 4))[0]
        require(pointer == int(entry['pointer'], 16), '虚表槽指针不符')
        for thunk in entry['thunks']:
            check(thunk)
            thunks[thunk['va']] = thunk
    require(next(item for item in vtable['entries'] if item['slot'] == '0x10')['implementation'] == '0x739500',
            'UI77消费者不符')

    rtc = json.loads((EVIDENCE / 'rtc_buffer.json').read_text(encoding='utf-8'))
    require(rtc['disk_sha256'] == digest, 'RTC版本指纹不同')
    for span in rtc['byte_ranges']:
        check(span)
    require(struct.unpack('<II', disk(0x65E77F, 8)) == (1, 0x65E787) and
            struct.unpack('<iII', disk(0x65E787, 12)) == (-144, 128, 0x65E793),
            '401D局部缓冲RTC容量不符')

    # 身份核验复用动态专题现有原证，不再复制或计为本地新增函数。
    reused_path = HERE.parent / '动态物件同步与触发/证据/dynamic_dependencies.json'
    reused = json.loads(reused_path.read_text(encoding='utf-8'))
    identity = next(item for item in reused['functions'] if item['va'] == '0x64f710')
    for chunk in identity['byte_ranges']:
        check(chunk)
    review.append({'va': '0x64f710', 'status': '复用既有专题结论',
                   'conclusion': '比较包内WORD身份与G+83844，不符弹Error GmsvID并退出。',
                   'unknown': '重发、包长和会话生命周期由网络专题维护。',
                   'evidence': '../动态物件同步与触发/证据/dynamic_dependencies.json/functions/0x64f710'})

    resources = json.loads((EVIDENCE / 'resources.json').read_text(encoding='utf-8'))
    sources = resources['records'] + resources['mappings'] + resources['picture_headers']
    for item in sources:
        require(hashlib.sha256((PROJECT / item['source']).read_bytes()).hexdigest() == item['sha256'],
                '资源指纹变化：' + item['source'])
    labels = {item['fields'].get('ID') for item in resources['records'][0]['sections']}
    require({'10', '20', '21', '22', '23', '24'} <= labels, '等待窗口控件ID缺失')
    mappings = resources['mappings'][0]['sections']
    require(sum(item['section'].startswith('O_24_S_') for item in mappings) == 30, '提示图变体不再是30个')
    for path in HERE.glob('*.txt'):
        for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            require(not line.strip() or line.startswith('//'), f'正文不是注释格式：{path.name}:{number}')

    (HERE / '函数审阅清单.json').write_text(json.dumps({
        'scope': '本专题局部结论；共享函数地址不得跨专题重复计为新增完成，两个大型函数仅局部审阅。',
        'functions': review}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    result = {'disk_sha256': digest, 'local_function_count': len(functions), 'reused_function_count': 1,
              'review_count': len(review), 'instruction_count': instruction_count,
              'instruction_bytes': instruction_bytes, 'unique_e9_thunks': len(thunks),
              'vtable_bytes': 96, 'rtc_data_bytes': 20, 'source_resource_count': len(sources),
              'all_current_disk_bytes_match': True, 'all_source_hashes_match': True,
              'scope': '仅静态字节、ABI文本断言和资源指纹；不代表实机通信、绘制或动画回执验证'}
    (HERE / '验证结果.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
