"""从固定调用顺序生成已人工审阅的61项颜色字段清单；不把最近字符串当完整控制流。"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main():
    data = json.loads((HERE / 'color_calls.json').read_text(encoding='utf-8'))
    groups = {}
    for row in data['sites']:
        groups.setdefault(row['owner_va'], []).append(row)
    expected = {}

    def direct(owner, keys, offsets):
        return [dict(owner=owner, key=key, kind='direct', offset=offset,
                     conclusion=f'颜色结果直接写控件+{offset}，DWORD；不拆通道')
                for key, offset in zip(keys, offsets)]

    def style(owner, key, base):
        return [dict(owner=owner, key=key, kind='style', base_offset=base, state=state,
                     offset=base+40*state+32,
                     conclusion=f'调用610B6B/8E1C40，style=控件+{base}，state={state}，写控件+{base+40*state+32}')
                for state in range(4)]

    public = []
    for channel, base in [('B', 56), ('F', 72)]:
        public += direct('0x8e4ff0', ['Hint'+channel+'Color']*3, [base, base+4, base+8])
        public += direct('0x8e4ff0', ['HintNormal'+channel+'Color', 'HintMouseIn'+channel+'Color',
                                    'HintMouseDown'+channel+'Color',
                                    'HintDisable'+channel+'Color | Hint'+channel+'Color'],
                         [base, base+4, base+8, base+12])
        public[-1]['shared_tail'] = True
        public[-1]['conclusion'] += '；共享尾部，通用键存在时来源为通用键，否则来源为Disable键'
    public += style('0x8e4ff0', 'BColor', 164)
    for state, name in enumerate(['Normal', 'MouseIn', 'MouseDown', 'Disable']):
        public.append(dict(owner='0x8e4ff0', key=name+'BColor', kind='style', base_offset=164,
                           state=state, offset=164+40*state+32,
                           conclusion='在通用BColor之后按单状态覆盖；调用610B6B/8E1C40'))
    expected['0x8e4ff0'] = public
    expected['0x8ee7b0'] = sum([style('0x8ee7b0', 'Btn'+str(i)+'BColor', 576+176*i) for i in range(3)], [])
    expected['0x904480'] = style('0x904480', 'BtnBColor', 576)
    listbox = []
    for name, state in [('Nor', 0), ('Down', 2), ('In', 1), ('Dis', 3)]:
        listbox.append(dict(owner='0x8f8080', key=name+'BColor', kind='style', base_offset=596,
                            state=state, offset=596+40*state+32,
                            conclusion='列表背景style使用通用状态0/2/1/3；调用610B6B/8E1C40'))
    listbox += direct('0x8f8080', [name+'FontColor' for name in ['Nor', 'Down', 'In', 'Dis']], [148, 152, 156, 160])
    for name, offset in zip(['Nor', 'Down', 'In', 'Dis'], [132, 136, 140, 144]):
        row = direct('0x8f8080', [name+'FontColor'], [offset])[0]
        row['presence_key'] = name+'FontBColor'
        row['conclusion'] += '；检查FontBColor存在但取FontColor值，当前兼容异常'
        listbox.append(row)
    expected['0x8f8080'] = listbox
    expected['0x900cd0'] = direct('0x900cd0', ['CheckColor'], [872])
    expected['0x901d30'] = direct('0x901d30', ['TopColor'], [608])
    expected['0x90a8f0'] = direct('0x90a8f0', ['CheckColor'], [596])
    names = ['Normal', 'MouseIn', 'MouseDown', 'Disable']
    expected['0x90d9b0'] = direct('0x90d9b0', [n+'CapFontFColor' for n in names], [148, 152, 156, 160])
    expected['0x90d9b0'] += direct('0x90d9b0', [n+'CapFontBColor' for n in names], [132, 136, 140, 144])
    assert set(groups) == set(expected)
    reviews = []
    for owner in sorted(groups):
        sites = sorted(groups[owner], key=lambda r: int(r['site'], 16))
        assert len(sites) == len(expected[owner])
        for site, row in zip(sites, expected[owner]):
            row['site'] = site['site']
            row['status'] = '调用点局部已审阅'
            row['scope'] = '属性取值、颜色转换后EAX存储或四态setter传参；非完整owner审阅'
            row['unknown'] = '其它owner路径、间接调用和渲染通道解释未展开'
            row['evidence'] = ['证据/color_calls.json']
            reviews.append(row)
    assert len(reviews) == 61
    payload = dict(scope='按保存的61个call逐项核对；共享控制流单列，不据最近属性名猜来源', sites=reviews)
    (HERE.parent / '调用点审阅清单.json').write_text(json.dumps(payload, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')


if __name__ == '__main__':
    main()
