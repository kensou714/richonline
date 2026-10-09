"""逐字节验证4023系列原证并输出人工语义分级；不以导出数量冒充业务闭环。"""
from pathlib import Path
import collections
import hashlib
import json
import struct

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[4]
blob = (ROOT/'RnClient.exe').read_bytes()
pe = struct.unpack_from('<I', blob, 0x3c)[0]
image_base = struct.unpack_from('<I', blob, pe+52)[0]
count = struct.unpack_from('<H', blob, pe+6)[0]
optional_size = struct.unpack_from('<H', blob, pe+20)[0]
sections = [struct.unpack_from('<IIII', blob, pe+24+optional_size+40*i+8) for i in range(count)]


def readva(ea, size):
    for virtual_size, rva, raw_size, raw_offset in sections:
        delta = ea-image_base-rva
        if 0 <= delta and delta+size <= raw_size:
            return blob[raw_offset+delta:raw_offset+delta+size]
    return None


def verify(row):
    disk = readva(int(row['va'], 16), row['size'])
    assert disk is not None, row['va']
    assert disk.hex() == row['disk_hex'] == row['idb_hex'], row['va']
    assert row['matching'] is True, row['va']


# 每项结论均人工提供；本体完整不代表递归依赖、自然名称或实机已完成。
complete = {
 '629e10': ('参数等于4返回真，供63E990模式判定', 'mode4官方玩法名未在此恢复'),
 '63e340': ('返回position+地图width', '输入格号合法性由上游保证'),
 '63e370': ('返回position-1', '行边界不在此检查'),
 '63e390': ('返回position-地图width', '输入格号合法性由上游保证'),
 '63e3c0': ('返回position+1', '行边界不在此检查'),
 '63e880': ('地形数组map+48的8字节记录首signed BYTE不为-1即真', '位置数组范围不检查'),
 '63e990': ('读地图+24并调用629E10，判mode4', '模式装载与官方名称未展开'),
 '63ea60': ('x>=0且x<地图width', 'width的有效性依赖地图加载'),
 '63eac0': ('y>=0且y<地图height', 'height的有效性依赖地图加载'),
 '63f760': ('比较G+3624当前行动槽与G+8本地槽', '当前行动者更新链见阶段专题'),
 '63f7b0': ('读取角色P+576附属对象指针', '附属对象完整业务名未恢复'),
 '63f810': ('DWORD[地图+144]>0返回真', '此配置字段的自然名称未确认'),
 '641250': ('附属对象+68格号、+64清0、+72/+76设64*x+64及48*y+48', '附属对象消费者与格号范围不在此证明'),
 '64f710': ('包内WORD身份与G+83844比较，不符弹Error GmsvID', '错误后的服务端重发策略未展开'),
 '64fb10': ('设置G+12时长及G+16当前tick作为基础队列门控', '不等于pending计时器，帧调度影响实际时序'),
 '65f0c0': ('4023两signed WORD物品各入数量1，提示只用第二返回值，再按两标志排后继', '请求来源、标志全部生产者和实际入槽需运行证据'),
 '65f410': ('4024首槽非-1才对四signed BYTE槽提示与扣1，末尾按两标志恢复', '重复槽/非法槽及请求来源的上层约束未证明'),
 '660160': ('4029排声音14、向当前角色入一个物品、提示后6080阶段2', '资源合法域和入槽结果不能只由成功包判定'),
 '660670': ('402C写奖金并同步通知UI19号码/中奖槽，暂停6400后排608A参数2', '未验证UI创建、实机派奖和服务器账本同步'),
 '660780': ('402D空处理器，无校验/字段消费/等待恢复', '其他版本与服务器使用意图未知'),
 '6607a0': ('402E按signed BYTE更新当前角色方向及后继附属位置，显示幽灵转向提示', '为何无需阶段后继及服务端完成链未闭环'),
 '67d7f0': ('6001按编号和选项播放声音，+6真才用时长或默认1800暂停', '实际音频播放需音频系统与实机'),
 '67d880': ('6002按演员更新头像、有效role才显示UI9/播放角色音效，按+6暂停', 'UI9内部表现与全部编号资源映射未展开'),
 '67da40': ('6003分别处理显示/关闭/暂停字段，窗口与队列时长独立', 'UI槽合法性、文本生存期和窗口内部依赖未穷尽'),
 '67db40': ('6004只读+2 WORD/+4 DWORD转入pending设置，不读actor+8', 'pending自动动作见等待专题'),
 '67dbe0': ('6006参数真且三角色状态为-1才启用操作，否则禁用', '其他全局抑制与各状态名称不能由此推出'),
 '681380': ('6080阶段0/1/2依返回值续1/2/6，6直接调用末阶段', '大阶段子函数不在本函数覆盖内'),
 '681c40': ('608A将signed BYTE参数交7C0C50并初始化scratch为0', '7C0C50完整回合业务仍局部'),
 '693260': ('6002构造号、+5=0/+6=1/+8=0，其他调用者补字段', '未写字节不能当保留零'),
 '6932b0': ('6003构造号，清+4/+5/+6及+8/+12/+16/+20', '构造不整体清24字节'),
 '693370': ('物品名指针=属性base+1128*id+660', 'id及文本长度没有本地检查'),
 '693420': ('6001构造号并清+4/+5/+8，子编号和+6需调用者填写', '其他字节不统一初始化'),
 '693830': ('608A构造只写WORD消息号', '参数及剩余字节由调用者负责'),
 '693950': ('6004构造只写WORD消息号', '类型、时长和actor由调用者负责'),
 '693980': ('6006构造只写WORD消息号', '操作字节由调用者负责'),
 '693be0': ('6080构造号和+3=-1，不写阶段+2', '有效阶段依调用点'),
 '694020': ('写this+36 DWORD；402C用于开奖奖金', '其他对象调用语义不由自动MFC名称推定'),
 '694bf0': ('角色声音ID=编号+1000*(role+1)', '声音资源存在与播放结果待音频系统核验'),
 '694c20': ('读取角色+40资源ID是否不为-1', '不检查role有效上界'),
 '694c50': ('清局部通知+8/+9 BYTE与+12 DWORD', '不推定该通知的所有构造字节'),
 '6e77b0': ('UI19分配92字节并调用6FB300', '基础UI构造依赖未递归分析'),
 '6fb300': ('基础构造后设置UI19虚表A25170', '其他基础虚函数未全部恢复'),
 '714bc0': ('UI19控件300注册事件19回调', '通用回调分派与提示内部未展开'),
 '714c70': ('保存号码/中奖槽、阶段0与tick，奖金写300用户数据，提交声音15并保存句柄', '未核验重复通知/提前关闭和音频真实句柄'),
 '714d30': ('UI19四阶段：动画、显示号码、无人累积或现金派奖/重置、终态', '帧停止、窗口失败、退出位W+88和服务端同步未闭环'),
 '715140': ('1..32号码控件随机四方向移动5..13像素并依据容器尺寸限边', '通用控件坐标依赖及尺寸异常未展开'),
 '727cf0': ('读取控件+188 DWORD图像ID', '图像资源合法性需图像系统保证'),
 '728280': ('读取this+36 DWORD，UI19用于开奖奖金', '金额合法域由其他层保证'),
 '728300': ('返回G+3164开奖数据子对象', '子对象全部构造与号码拥有者生产者未展开'),
 '798350': ('写this+12 DWORD，方向链用于P+864内嵌对象', '渲染对象完整布局未恢复'),
 '7d5e10': ('BYTE[G+83830]不为-1返回真', '状态全部写入来源未恢复'),
 '7d6d70': ('比较DWORD[G+3628]与G+3624当前槽', '两个行动字段的全生命周期未展开'),
 '7d9c70': ('开奖对象BYTE+1..32设-1并将奖金DWORD+36设5000', '无人中奖不调用此重置，号码拥有者装载待查'),
 '7e14a0': ('按四方向检查当前位置下一格x/y边界，非法方向返回假', '原始格号与width非零依地图约束'),
 '7e1580': ('按四方向返回pos+width/-1/-width/+1，默认-1', '边界检查是调用者职责'),
 '7e1600': ('signed除/余数拆position为x/y', '没有width为0防护'),
 '7f7940': ('写P+1460方向并同步P+864对象+12', '方向值域与渲染完整业务未知'),
 '7f7990': ('地图+144真时取反方向邻格，地形无效回退，写附属位置及P+536', '没有直接写P+1464，附属完成契约需另追'),
 '7f7cf0': ('P+1488有效则递减P+1490；正值返回-1，非正返回P+1488', '两角色BYTE的官方状态名未恢复'),
 '7f86a0': ('按group0/1/2读六字节库存槽ID，非法组-1', 'slot无范围检查，重复槽上游不去重'),
 '7f8920': ('group0槽WORD数量扣减，非正清空并通知本地库存刷新', '非法槽与signed计数合法域由上游保证'),
 '7fa050': ('现金P+1504增加金额，通知参数真时调用金额通知', '32位溢出无保护，服务器账本需独立确认'),
 '7fb200': ('懒初始化63项头像帧选择表，19映射5、10映射3', '索引无边界检查，官方表情名未恢复'),
 '7fd7a0': ('只返回BYTE[P+1416]；7F8780以其非零强制返回1', '该角色字节的业务用途及写入来源待查，不是已确认的库存全满谓词'),
}
partial = {
 '63e5b0': ('ECX改为G+1600后取队列head，伪码CDialog命名不可信', '队列getter内部沿用基础队列专题'),
 '63eca0': ('两模式谓词或运算，用于608A参数2奖励路径选择', '两个底层模式谓词未在本篇重新导出'),
 '64fa50': ('指定长度复制到288字节栈槽，再以cursor和模式1插本地队列', '环形搬移/满队列策略复用既有队列专题'),
 '660860': ('复用动态物件专题：402F六个signed WORD格号立即写type12并排6001/6064', '没有新增地图算法完成声明，非法格/满队列仍待查'),
 '69a5d0': ('对象+8开关允许且+32句柄非0时停止并清句柄', '底层停止接口和其他声道见音频专题'),
 '7c0c50': ('608A参数2从LABEL126开始奖励/状态后继，绕过default换行动者主干', '全部回合分支、附加效果和官方状态仍未穷尽'),
 '7e2f00': ('参数2尾部可到动态type26持续值递减/归零清除，复用动态专题', '其他门控及运行节拍未在本篇完成'),
 '7e4c50': ('扫描6字节地产奖励记录，校验归属/条件、递减倒计时后排提示和6079', '奖励等级映射、资源许可与6079完整消费者未展开'),
 '7e51a0': ('扫描64个12字节奖励记录，条件失效清除，到期排提示/6079', '记录来源、角色状态值域和奖励合法域未完成'),
 '7f7670': ('写P+388头像帧并通知P+864内嵌对象', '渲染帧选择内部未展开'),
 '7f8780': ('空group0槽插入后可能合成；BYTE[P+1416]非零则强制返回1，否则返回入槽v7', 'P+1416用途与配方许可待查；本次插入成功不能仅由返回1判断'),
}

functions, thunks, snapshots = {}, {}, []
for path in sorted(BASE.glob('series_*.json')):
    data = json.loads(path.read_text(encoding='utf-8'))
    snapshots.append({'path': path.name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    if isinstance(data, list):
        for row in data:
            verify(row)
        continue
    assert data['disk_sha256'] == hashlib.sha256(blob).hexdigest(), path.name
    for f in data['functions']:
        for row in f['byte_ranges']:
            verify(row)
        assert f['bytes_match_disk'], f['va']
        if f['va'] in functions:
            assert functions[f['va']]['byte_ranges'] == f['byte_ranges']
        f['evidence_file'] = path.name
        functions[f['va']] = f
    for t in data['thunks']:
        verify(t)
        thunks[t['va']] = t

review = []
for va, f in sorted(functions.items(), key=lambda item: int(item[0], 16)):
    key = va[2:]
    candidates = [(level, rows[key]) for level, rows in [('已分析', complete), ('局部分析', partial)] if key in rows]
    assert len(candidates) == 1, va
    level, (conclusion, unknown) = candidates[0]
    review.append({'va': va, 'status': level, 'conclusion': conclusion, 'unknown': unknown,
                   'evidence': '证据/'+f['evidence_file']+'/functions/'+va,
                   'scope': conclusion, 'bytes_match_disk': True})
assert len(complete)+len(partial) == len(review)
counts = dict(collections.Counter(row['status'] for row in review))
resources = json.loads((BASE/'4023系列资源样本.json').read_text(encoding='utf-8'))
for row in resources['records']:
    current = (ROOT/row['source']).read_bytes()
    assert len(current) == row['size'] and hashlib.sha256(current).hexdigest() == row['sha256'], row['source']
manifest = {'scope': '本专题函数本体静态审阅，共享函数不等于新增覆盖，外部依赖不自动完成',
            'status_definitions': {'已分析': '所列函数本体全部可见分支与作用已阅读，不消除unknown',
                                  '局部分析': '仅conclusion列出的路径或复用范围已确认'},
            'counts': counts, 'functions': review}
(BASE.parent/'函数审阅清单.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
summary = {'disk_sha256': hashlib.sha256(blob).hexdigest(),
           'ida_input_sha256': 'cb35f69f3d49c2093897d4ea2cb547a1e38b213f3a8df0af52b859f9e661de77',
           'unique_functions': len(functions), 'semantic_counts': counts,
           'instruction_ranges': sum(len(f['byte_ranges']) for f in functions.values()),
           'instruction_bytes': sum(r['size'] for f in functions.values() for r in f['byte_ranges']),
           'unique_direct_thunks': len(thunks), 'function_mismatches': [], 'thunk_mismatches': [],
           'additional_data': 'UI19虚表172字节、四入口跳板和10字节工厂登记匹配',
           'current_resource_hashes_verified': len(resources['records']), 'evidence_snapshots': snapshots,
           'boundary': '只核导出的原证和资源源哈希；不证明服务端账本、运行时对象或实机时序'}
(BASE/'核验汇总.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
print(json.dumps({'unique_functions': len(functions), 'counts': counts,
                  'instruction_bytes': summary['instruction_bytes'], 'thunks': len(thunks)}, ensure_ascii=False))
