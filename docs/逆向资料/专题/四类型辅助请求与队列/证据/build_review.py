"""生成作者逐函数台账；结论人工填写，原证与机器指令锚点机械绑定。"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
NOTES = {
    '0x859a80': ('循环遍历ACB8F8并销毁连接，再遍历ACB8E8并delete元素；iterator/erase未全展开，不证明彻底clear。', '两容器深iterator、erase与并发状态未闭合。'),
    '0x85a1e0': ('构造type0/body64共74字节包，两个strncpy32槽；创建连接和buffer、复制后入队，返回本地helper结果。', '第二槽变换算法、业务身份、分配异常及运行可达性未全核。'),
    '0x85a4e0': ('构造type1/body96共106字节包，三个strncpy32槽；连接和buffer构造后复制入队。', '第二槽变换算法、业务身份及分配异常未全核。'),
    '0x85a7a0': ('构造type2/body96共106字节包，三个strncpy32槽；连接和buffer构造后复制入队。', '第二槽变换算法、业务身份及分配异常未全核。'),
    '0x85aa60': ('构造type3/body64共74字节包，两个strncpy32槽；连接和buffer构造后复制入队。', '当前主范围无直接入边，运行可达性及第二槽算法未知。'),
    '0x85ad70': ('构造type4/body97共107字节包；三槽加实参低BYTE，入队后遍历本地元素并按strncmp32命中更新+33。', 'type4响应契约、+33业务身份与失败回滚未知；iterator比较/取值外依赖未全核。'),
    '0x858b20': ('连接字段+8=0、+0C=0、+10=1、+14=-1，+18内嵌容量10buffer，+28=0；未初始化socket/event。', '分配失败及异常元数据不证明完整异常安全。'),
    '0x858dc0': ('清零ACB8C4的32字节，strlen输入后调用8613C0，返回共享输出地址。', '861670变换核心、输出表示及并发保护未知。'),
    '0x859c50': ('调用858BC0连接析构，再按实参低bit执行operator delete(this)，retn4。', '分配器、CRT内部与运行线程未全核。'),
    '0x85a3e0': ('调用公共头构造，写type0/body64并对body清零。', '业务名及上层参数身份未知。'),
    '0x85a710': ('调用公共头构造，写type1/body96并对body清零。', '业务名及上层参数身份未知。'),
    '0x85a9d0': ('调用公共头构造，写type2/body96并对body清零。', '业务名及上层参数身份未知。'),
    '0x85ac60': ('调用公共头构造，写type3/body64并对body清零。', '运行可达性、业务名及参数身份未知。'),
    '0x85b010': ('调用公共头构造，写type4/body97并对body清零。', 'type4正确响应契约及业务名未知。'),
    '0x85b0a0': ('functor+0写输入指针、+4只写输入低BYTE，retn8；其余填充未写明。', '填充值不确定，业务字段身份未知。'),
    '0x85b280': ('调用empty谓词；非空对front slot调用空析构，再first递增环回、count递减，空时first归零。', 'empty谓词85B1D0及容器整体约束未采本体。'),
    '0x85b380': ('以first+count寻尾槽，必要扩容/分配块，调用85C150拷贝DWORD指针值后count加1，retn4。', '85BE10扩容、85C0F0分配实现及整数边界未闭合。'),
    '0x85b4d0': ('构造临时iterator，经85C800与85BC70包装单项erase，返回隐藏结果对象地址。', 'iterator构造及erase依赖未全闭，不证明clear完成。'),
    '0x85d700': ('逐元素调用85ACF0并无条件推进iterator，忽略返回值；结束后复制functor两DWORD到隐藏结果。', '比较和解引用wrapper未全展开；functor第二DWORD填充未写明。'),
    '0x860fb0': ('+0C保存容量，operator new(capacity)结果写+0，调用8612F0清零storage及复位游标。', '分配器失败路径与完整异常元数据未核。'),
    '0x861190': ('ECX为buffer，直接读readPtr的DWORD再推进4；无栈参数、普通retn，纠正错误callback(type,3)。', '输入buffer剩余至少4由调用者保证，业务错误码意义未知。'),
    '0x861270': ('取writePtr，memcpy调用者Size，再推进writePtr；this/两个栈参数，retn8。', '本地无边界检查；输入合法性及CRT实现未全核。'),
    '0x858bc0': ('释放非零sendBuffer；initiated非零时释放bodyBuffer并关闭event/socket；最后析构内嵌buffer。', '有效句柄与运行时关闭错误未核；不宣称完整异常安全。'),
    '0x858d50': ('调用861040释放buffer.storage，再按实参bit0释放buffer对象，retn4。', 'CRT分配器内部未核。'),
    '0x859850': ('返回buffer+8 writePtr；无栈参数。', '游标合法性由调用者保证。'),
    '0x8598e0': ('buffer+8 writePtr加栈上增量，返回this，retn4，无本地边界检查。', '允许输入范围与溢出约束由调用者保证。'),
    '0x85a0b0': ('返回buffer+4 readPtr；无栈参数。', '游标合法性由调用者保证。'),
    '0x85a0f0': ('返回capacity-(readPtr-storage)，普通retn，不以writePtr计算有效数据量。', '对象状态合法性由调用者保证。'),
    '0x85a140': ('buffer+4 readPtr加栈上增量，返回this，retn4，无本地边界检查。', '增量合法性与溢出约束由调用者保证。'),
    '0x85a190': ('buffer+4 readPtr复位为+0 storage，返回this，普通retn。', 'storage有效性由调用者保证。'),
    '0x85a470': ('写CRLF两个BYTE，+2 type=-1，+6 bodyLength=0，返回this，普通retn。', '公共头后的body容量由具体构造保证。'),
    '0x85acf0': ('strncmp(element,functor指针,32)为0时写element+33=functor+4 BYTE；retn4。', '+33业务意义、元素有效性及编码未知。'),
    '0x85bc70': ('按距离比较选择两侧搬移，再重复popfront或另一pop接口，返回结果iterator。', '85D2E0距离、85D890/85D930搬移、85CA30与85C800未全核。'),
    '0x85c150': ('转发slot与源指针地址至85DBB0，并retn8；本体只适配allocator接口。', 'placement new运行库内部未全核。'),
    '0x85c1b0': ('转发slot至85DC50并retn4；真实slot析构为空，不删除pointee。', '容器其他释放路径不由此函数证明。'),
    '0x85df90': ('iterator首DWORD加4，返回this；普通retn。', 'end边界由上层比较与容器契约保证。'),
    '0x8612f0': ('按capacity清零storage，调用85A190与861370分别复位readPtr/writePtr，普通retn。', 'storage有效性与memset运行库内部未核。'),
    '0x8613c0': ('调用临时变换对象构造/处理/getter，拷贝min(a4,32)字节到输出，随后析构；普通retn。', '8615A0/861670/8617F0/8614F0尚未采，算法不能命名密码或hash。'),
    '0x85dbb0': ('placement new(4,slot)后将源地址中的DWORD指针值写slot，不复制pointee；普通retn。', 'placement new运行库内部未全核。'),
    '0x85dc50': ('仅调试栈初始化与恢复；无对象访问/释放/call，普通retn。', '调用者容器其余生命周期不由空析构证明。'),
    '0x861040': ('operator delete(buffer+0 storage)，普通retn；不复位buffer字段。', 'CRT释放器内部与调用者对象生命周期未全核。'),
    '0x861370': ('buffer+8 writePtr复位为+0 storage，普通retn。', 'storage有效性由调用者保证。'),
}


def semantic_anchor(ins):
    text = ins['text']
    return any(mark in text for mark in ('call ', 'call    ', 'retn', 'cmp ', 'cmp     ',
                'jnz ', 'jz ', 'jmp ', 'mov     [eax', 'mov     [ecx',
                'mov     [edx', 'mov     dword ptr [', 'mov     byte ptr [',
                'mov     eax, [eax', 'mov     ecx, [eax', 'add     ecx,',
                'add     eax,', 'sub     ecx,', 'shr ', 'div ')) and \
        not any(mark in text for mark in ('RTC', 'esp', 'ebp', 'fs:'))


def build():
    functions = []
    sources = ['formal_functions.json', 'dependency_raw.json',
               'dependency_helpers_raw.json', 'dependency_leaf_raw.json']
    lookup = {}
    for name in sources:
        raw = json.loads((HERE / name).read_bytes())
        for index, row in enumerate(raw['functions']):
            lookup[row['va']] = (name, index, row)
    cross_refs = {
        '0x85a1e0': ['0x85a3e0', '0x85a470', '0x85dbb0'],
        '0x85a4e0': ['0x85a710', '0x85a470', '0x85dbb0'],
        '0x85a7a0': ['0x85a9d0', '0x85a470', '0x85dbb0'],
        '0x85aa60': ['0x85ac60', '0x85a470', '0x85dbb0'],
        '0x85ad70': ['0x85b010', '0x85a470', '0x85d700', '0x85acf0'],
        '0x859c50': ['0x858bc0'], '0x858bc0': ['0x858d50', '0x861040'],
        '0x858d50': ['0x861040'], '0x858b20': ['0x860fb0'],
        '0x860fb0': ['0x8612f0', '0x85a190', '0x861370'],
        '0x8612f0': ['0x85a190', '0x861370'],
        '0x85b280': ['0x85c1b0', '0x85dc50'],
        '0x85b380': ['0x85c150', '0x85dbb0'],
        '0x85c150': ['0x85dbb0'], '0x85c1b0': ['0x85dc50'],
        '0x861190': ['0x85a0b0', '0x85a140'],
        '0x861270': ['0x859850', '0x8598e0'],
        '0x85d700': ['0x85acf0', '0x85df90'],
    }
    for name in sources:
        payload = (HERE / name).read_bytes()
        raw = json.loads(payload)
        for index, row in enumerate(raw['functions']):
            conclusion, unknown = NOTES[row['va']]
            path = '证据/' + name
            root_pointer = '/functions/' + str(index)
            anchors = [dict(path=path, pointer=root_pointer + '/assembly/' + str(i) + '/text',
                            value=ins['text'], site_va=ins['va'])
                       for i, ins in enumerate(row['assembly']) if semantic_anchor(ins)]
            evidence = [path]
            for va in cross_refs.get(row['va'], []):
                dep_name, dep_index, dep = lookup[va]
                dep_path = '证据/' + dep_name
                if dep_path not in evidence:
                    evidence.append(dep_path)
                anchors += [dict(path=dep_path,
                    pointer='/functions/' + str(dep_index) + '/assembly/' + str(i) + '/text',
                    value=ins['text'], site_va=ins['va'], dependency_va=va)
                    for i, ins in enumerate(dep['assembly']) if semantic_anchor(ins)]
            # 空析构没有机器语义写入，返回点本身就是无副作用边界锚点。
            assert anchors, row['va']
            functions.append(dict(va=row['va'], name_from_idb=row['name'],
                status='局部语义已审阅', review_status='局部语义已审阅',
                conclusion=conclusion, unknown=unknown, evidence=evidence,
                anchors=anchors, full_dependency_closure=False,
                declared_chunks=row['declared_chunks'],
                original_byte_ranges=row['chunk_byte_ranges'],
                source_records=[dict(path=path, sha256=hashlib.sha256(payload).hexdigest(),
                                     pointer=root_pointer)]))
    assert len(functions) == len(NOTES) == 42
    assert len({f['va'] for f in functions}) == 42
    result = dict(scope='第二十一批42个声明入口的局部语义审阅；静态本体与有限依赖，非全依赖闭环或实机验证',
                  disk_sha256=raw['disk_sha256'], functions=functions,
                  reused_ranges=dict(path='证据/reused_network.json', count=4,
                    new_completion_count=0, note='旧单区间逐PE重核；不补造旧声明chunks或提升新完成数'),
                  source_files=[dict(path='证据/' + name,
                    sha256=hashlib.sha256((HERE / name).read_bytes()).hexdigest()) for name in sources])
    (HERE.parent / 'function_review.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(status='PASS', local_reviewed_functions=len(functions))


if __name__ == '__main__':
    print(json.dumps(build(), ensure_ascii=True))
