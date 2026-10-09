"""核验当前EXE与通知专题原证；语义分级不包含递归依赖或实机验证。"""
from pathlib import Path
import collections
import hashlib
import json
import struct

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[4]
blob = (ROOT / 'RnClient.exe').read_bytes()
pe = struct.unpack_from('<I', blob, 0x3c)[0]
image_base = struct.unpack_from('<I', blob, pe + 52)[0]
section_count = struct.unpack_from('<H', blob, pe + 6)[0]
optional_size = struct.unpack_from('<H', blob, pe + 20)[0]
sections = [struct.unpack_from('<IIII', blob, pe + 24 + optional_size + 40*i + 8)
            for i in range(section_count)]


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


# 已分析仅覆盖本体；unknown指出仍不可由该函数推出的上层事实。
complete = {
 '628270': ('单例A76728，缺对象分配0xABC并调用构造', '构造和单例线程安全未在本篇展开'),
 '63e160': ('读取地图+24并判等3，返回BOOL而非mode', '地图mode装载来源未展开'),
 '63e1a0': ('参数等于3返回真', 'mode3自然名称未据此命名'),
 '63e1e0': ('读取角色P+380头像ID DWORD', '头像字段装载见其他专题'),
 '63e210': ('返回G+1628地图子对象地址', '子对象完整布局未恢复'),
 '63e230': ('返回DWORD[G+3584+4*s]，无槽范围检查', '有效指针与s范围由上游保证'),
 '63e560': ('比较参数槽与G+8本地槽', '本地槽初始化未展开'),
 '63e7d0': ('读取BYTE[G+3632+s]', '该标志自然名称未确认'),
 '63f390': ('读取BYTE[G+3672+s]', '该标志自然名称未确认'),
 '63f5f0': ('读取角色P+1512点券DWORD', '结算不在getter中'),
 '63f840': ('按G+8取G+3584角色指针数组', '角色指针合法性未统一校验'),
 '64efa0': ('读取BYTE[G+3640+s]', '该标志自然名称未确认'),
 '662920': ('4041核验GmsvID后将两个signed BYTE转flags2通知', '长度和资源范围验证不在本体'),
 '691b70': ('读取角色P+40角色资源ID DWORD', '角色资源ID装载来源未展开'),
 '691bd0': ('读取BYTE[G+83831]作为提交抑制状态', '该状态所有写入来源待追踪'),
 '69afd0': ('按音频对象+52跨度与+56数组读取VoiceFace表情', '没有角色/槽范围检查'),
 '69b150': ('textID=(role<<8)+phrase+1664', '调用者合法域需另核'),
 '69b170': ('sndID=1000*(role+1)+phrase+128', '底层声音实际可播放性需实机'),
 '6fa210': ('读取控件+385 BYTE可见状态', '绘制效果依赖控件树'),
 '6fa270': ('读取控件+384 BYTE启用状态', '禁用状态与服务器权限不是同一事实'),
 '6fad70': ('UI0基础构造、A242D0虚表、三计时器及八个20字节槽', '基础类构造未递归分析'),
 '7053d0': ('九种掩码全部可见分支：头像、表情、气泡、语音、复活状态与提示', '通知生产者、资源合法域及服务端结算需另核'),
 '709d30': ('取type8头像资源expression+13帧', '图像缓存内部未展开'),
 '709d70': ('按四个面板data[0]查角色槽，ECX=this，retn4', '控件树完整性由初始化保证'),
 '709e00': ('清20字节角色UI槽的五个DWORD', '只说明槽构造，不推定所有W字段'),
 '727820': ('读取DWORD[G+3616]参与人数', '人数与八槽/四面板的约束待查'),
 '727850': ('本地金豆DWORD[G+1536+4*local]与金额比较', '比较不扣金额'),
 '727890': ('读取DWORD[G+8]本地槽，IDA的ATL命名不可信', '本地槽初始化待查'),
 '7278b0': ('读取BYTE[G+3664+s]', '该标志自然名称未确认'),
 '727980': ('请求构造仅WORD+0=24、BYTE+5=0，其他字节未写', '模式1未写+2的服务器消费待查'),
 '7f76c0': ('取type8头像P+380、帧P+388+1', '头像状态写入来源未展开'),
 '7fdb70': ('读取角色P+388头像帧DWORD', '字段完整业务枚举未恢复'),
 '81bc80': ('转交计时器阈值设置并返回this', '内部依赖已在81BCB0记录'),
 '81bcb0': ('写阈值与GetTickCount起始值', '不保证tick回绕稳定'),
 '81bd10': ('now>start且差值达到阈值才通过并更新start', '回绕时now<=start将返回假'),
 '8e1570': ('读control+420数组，index仅检查上界，无数组返回0', '负index没有防护'),
 '8e15b0': ('写control+420数组，index仅检查上界，无数组返回失败', '负index没有防护'),
}
partial = {
 '64fbd0': ('队列每约3000ms取项构造flags8，仅N[0]/N[1]/N[3]被写', '队列内部沿用诊断专题，公共门控未全部展开'),
 '69a540': ('语音入口两个开关、底层参数和可选句柄保存', '底层声道/缓存/播放系统见音频专题'),
 '6a7900': ('本篇545、末参0路径：8字节记录低12位ID与bit16', '末参非0的32槽关联查找、第二DWORD和资格来源待查'),
 '6e4640': ('同步转交UI0虚表+16通知', '通用UI前后保护依赖未全部展开'),
 '6fab30': ('转换多字节文本并写control+12文本对象', '转换规则及源指针生命周期未完整恢复'),
 '7045a0': ('计时器500/1000/1350、角色槽资源ID和W+432..435初始化', '其余控件回调与UI0状态字段仍未逐项解释'),
 '705c70': ('W+80通过时调用708330；其他复活闪烁相关尾部可见', '完整快捷键、提示与附加控件逻辑未完成'),
 '7061f0': ('复活按钮28/43/58/73条件、0018模式与字段初始化', '其他点击分支和服务端回复未完成'),
 '708330': ('四面板data[0]映射、mode3/4跳过条件及2700ms过期', '金额/图标/附加提示依赖和人数约束未全部展开'),
 '7094c0': ('Ctrl+F1..F8短句选择主干与1350ms提示隐藏', '快捷键映射、发送门控依赖由音频专题继续'),
 '7098c0': ('短句三组和四按钮分页文字刷新主干', '文本配置合法域与按钮提示依赖未全部展开'),
}

functions, thunks, snapshots = {}, {}, []
for path in sorted(BASE.glob('notify_*.json')):
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
    options = [(level, rows[key]) for level, rows in [('已分析', complete), ('局部分析', partial)] if key in rows]
    assert len(options) == 1, va
    level, (conclusion, unknown) = options[0]
    review.append({'va': va, 'status': level, 'conclusion': conclusion, 'unknown': unknown,
                   'scope': conclusion, 'evidence': '证据/'+f['evidence_file'],
                   'byte_ranges': len(f['byte_ranges']), 'bytes_match_disk': True})
assert len(complete)+len(partial) == len(review)
counts = dict(collections.Counter(row['status'] for row in review))
resource_sample = json.loads((BASE/'主界面资源样本.json').read_text(encoding='utf-8'))
for row in resource_sample['records']:
    current = (ROOT/row['source']).read_bytes()
    assert len(current) == row['size'], row['source']
    assert hashlib.sha256(current).hexdigest() == row['sha256'], row['source']
manifest = {'scope': '本专题静态审阅深度；共享函数不等于项目新增覆盖；依赖不自动完成',
            'status_definitions': {'已分析': '函数本体全部可见分支已阅读，外部业务仍有unknown',
                                  '局部分析': '仅conclusion列出的路径已确认，unknown须继续追踪'},
            'counts': counts, 'functions': review}
(BASE.parent/'函数审阅清单.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
summary = {'disk_sha256': hashlib.sha256(blob).hexdigest(),
           'ida_input_sha256': 'cb35f69f3d49c2093897d4ea2cb547a1e38b213f3a8df0af52b859f9e661de77',
           'unique_functions': len(functions), 'semantic_counts': counts,
           'instruction_ranges': sum(len(f['byte_ranges']) for f in functions.values()),
           'instruction_bytes': sum(r['size'] for f in functions.values() for r in f['byte_ranges']),
           'unique_direct_thunks': len(thunks), 'function_mismatches': [], 'thunk_mismatches': [],
           'current_resource_hashes_verified': len(resource_sample['records']),
           'additional_data': 'A242D0虚表172字节及四个入口5字节跳板逐字节一致',
           'evidence_snapshots': snapshots,
           'boundary': '只核已导出的原证；不保证未导出代码、运行时数据、服务端或游戏实机'}
(BASE/'核验汇总.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
print(json.dumps({'unique_functions': len(functions), 'counts': counts,
                  'instruction_bytes': summary['instruction_bytes'], 'thunks': len(thunks)}, ensure_ascii=False))
