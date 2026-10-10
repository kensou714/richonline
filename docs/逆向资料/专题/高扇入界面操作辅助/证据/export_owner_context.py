"""只读导出显式调用所在块及两层前驱；不把大函数导航窗计为完整审阅。"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def export(sites, destination, predecessor_depth=2):
    import ida_bytes
    import ida_funcs
    import ida_gdl
    import idautils
    import idc

    destination = Path(destination)
    assert not destination.exists()
    assert 0 <= predecessor_depth <= 2
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == EXPECTED_SHA
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + 40 * i + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def identity(start, end):
        assert start < end and end - start <= 4096
        matches = [(rva, off) for _, rva, size, off in sections
                   if 0 <= start - base - rva and end - base - rva <= size]
        assert len(matches) == 1
        rva, off = matches[0]
        disk = image[off + start - base - rva:off + end - base - rva]
        raw = ida_bytes.get_bytes(start, end - start)
        assert raw == disk
        return dict(size=end - start, idb_hex=raw.hex(), disk_hex=disk.hex(),
                    matching=True, sha256=hashlib.sha256(raw).hexdigest())

    windows, controls = {}, []
    for site in sites:
        owner = ida_funcs.get_func(site)
        assert owner is not None
        chart = ida_gdl.FlowChart(owner, flags=ida_gdl.FC_PREDS)
        block = next(b for b in chart if b.start_ea <= site < b.end_ea)
        queue, visited, links = [(block, 0)], set(), []
        while queue:
            block, depth = queue.pop(0)
            if block.start_ea in visited:
                continue
            visited.add(block.start_ea)
            assert len(visited) <= 16, '前驱数量超过有限上限'
            heads = list(idautils.Heads(block.start_ea, block.end_ea))
            assert 0 < len(heads) <= 256
            key = (owner.start_ea, block.start_ea, block.end_ea)
            if key not in windows:
                rows = []
                for head in heads:
                    end = min(ida_bytes.get_item_end(head), block.end_ea)
                    rows.append(dict(site_va=hex(head),
                                     text=idc.generate_disasm_line(head, 0) or '',
                                     is_code=bool(ida_bytes.is_code(ida_bytes.get_full_flags(head))),
                                     bytes=identity(head, end)))
                windows[key] = dict(owner_va=hex(owner.start_ea),
                                    start_va=hex(block.start_ea), end_va=hex(block.end_ea),
                                    scope='有限上层代码导航；不认领owner完整语义',
                                    assembly=rows, **identity(block.start_ea, block.end_ea))
            predecessors = list(block.preds())
            links.append(dict(block_start_va=hex(block.start_ea), depth=depth,
                              predecessor_start_vas=[hex(b.start_ea) for b in predecessors],
                              successor_start_vas=[hex(b.start_ea) for b in block.succs()]))
            if depth < predecessor_depth:
                queue.extend((b, depth + 1) for b in predecessors)
        controls.append(dict(site_va=hex(site), owner_va=hex(owner.start_ea),
                             blocks=links, predecessor_depth=predecessor_depth))
    result = dict(disk_sha256=EXPECTED_SHA,
                  exporter_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  scope='显式调用块及有限前驱；不证明路径实机可达或owner全函数语义',
                  controls=controls, windows=list(windows.values()))
    with destination.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    return dict(windows=len(windows), output=str(destination))
