"""保存逐函数人工结论，不以仿真次数替代业务分析等级。"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROWS = [
    (0x9213A0,'静态契约已审阅','cdecl字节复制；重叠时按方向搬移，DF=0及有效不回绕区间为前提。'),
    (0x9217B0,'静态契约已审阅','同型字节复制；补独立反向对齐跳表解码，支持左右重叠。'),
    (0x62BA10,'静态契约已审阅','三栈参数转9213A0；返回目标指针，不增加长度与所有权检查。'),
    (0x62BDE0,'静态契约已审阅','三栈参数转9217B0；memcpy_0自动名不限制此二进制重叠能力。'),
    (0x62BD10,'复用并闭合局部契约','复用短字符串删除审阅，闭合合法同缓冲左移重叠；原机器码删除链离线仿真通过。'),
]


def main():
    rows = [dict(va=hex(a),status=s,conclusion=c,
                 unknown='未实机；不证明无效/回绕指针或任意DF输入，不证明所有CRT实例。',
                 evidence='证据/crt_copy.json') for a,s,c in ROWS]
    payload=dict(counts={'静态契约已审阅':4,'复用并闭合局部契约':1},functions=rows)
    (HERE/'函数审阅清单.json').write_text(json.dumps(payload,ensure_ascii=False,indent=2),encoding='utf-8',newline='\n')


if __name__ == '__main__':
    main()
