"""登记逐函数人工结论；代码导出、局部契约和复用项分开统计。"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONTRACTS = {
    '6dc650': '就绪、槽检查及按需加载后转float矩形并绘制，随后无条件递增槽使用计数。',
    '6dc730': '就绪、槽检查及按需加载后按对象位置绘制，随后递增使用计数。',
    '6dc7d0': '就绪后将整数矩形转float，转交全局无纹理图像的颜色与矩形绘制。',
    '6dc850': '就绪后写两个stride28顶点xy/颜色，提交2顶点2索引的类型2单图元。',
    '6dc8f0': '逐轮绘四边并向内收缩1像素，厚度非正无绘制；内部使用全局管理器。',
    '6dcba0': '已加载对象的current==count-1返回真；不加载、不验证范围、不证明停止。',
    '6dcc00': '已有槽对象时只清当前帧号；不重置计时，不校验槽。',
    '6dcc40': '已有槽对象时读取原图透明位，非0归一为true；空槽false，坐标不裁剪。',
    '6dcd60': '范围检查及按需加载后恢复原图四顶点并启用裁剪；无就绪门槛。',
    '6dcdd0': '范围检查及按需加载后将整数支点、角度传旋转消费者；无使用计数递增。',
    '6dc090': '固定loaded/4轮扫描，选最后合格槽；阈值FFFFFFFF不更新，无候选仍释放0。',
    '6dfad0': '读取manager+630756中指针所指BYTE；不检查指针、不等于包模式开关。',
    '6dfb40': 'pixel=x+DWORDwidth*y；sar3求byte索引，低3位求透明掩码bit；返回位原值。',
    '813410': '构造原图四顶点(0,h),(0,0),(w,h),(w,0)，调用位置更新并置+172=1。',
    '8134f0': '比较四顶点；+173=0只更新CPU，非0时成功锁VB才更新CPU及stride28 xy。',
    '8136d0': '比较四DWORD颜色；成功锁VB后更新CPU+128及各stride28颜色+16。',
    '813810': '比较四UV对；成功锁VB后更新CPU+64及各stride28 UV+20/+24。',
    '814120': '先启用+173；按+172以现有顶点矩形裁剪，再调用绘制核心。',
    '814320': '复制外部矩形，启用+173，按+172裁剪或直接设置四顶点，再绘制。',
    '814400': '按全局矩形裁剪并按原宽高修UV；无重叠禁用+173；无零除数保护。',
    '814930': '对全局图像ABA790更新四颜色，再按给定矩形绘制。',
    '814970': '创建16字节缓冲包装，分配stride28顶点与WORD索引；部分失败仅删包装。',
    '814c10': '非空接口各Release并清槽；不删除16字节包装。',
    '814cd0': '容量不足销毁重建，再上传xy/颜色及WORD索引；重建失败未判空。',
    '814ec0': '先上传再判全局就绪，固定设备状态提交；忽略上传结果、不保存旧状态。',
    '818bb0': '返回全局ABA7C4 BYTE作为绘制就绪条件。',
    '818bc0': '将参数低BYTE写入图像+172。',
    '818be0': '将参数低BYTE写入图像+173。',
    '818c00': '读取图像+173 BYTE。',
    '818c20': 'ECX原值返回，不初始化矩阵元素。',
    '818c40': '读取图像+172 BYTE。',
    '6e5100': 'x/y减1并下界归0，直接槽命中取反透明位；空槽因此命中true。',
    '6e5160': 'x/y减1并下界归0，名称解析成槽后取反透明位；第三参数是字符串。',
}
PARTIAL = {
    '813b20': ('角度转弧度，顶点减支点，经间接矩阵分派后加回，写位置并禁用矩形裁剪。',
               '真实运行态矩阵实现、旋转方向和归一化未展开；不据默认槽假定算法。'),
    '95e781': ('经A6AB00间接转交矩阵调用参数。', '槽经懒初始化改写；实际算法未审。'),
    '95c7eb': ('经A6AB74间接转交向量消费调用。', '实际参数类型及分派后算法未审。'),
    '95e75e': ('先977A09(1)初始化，再经A6AB00重试；磁盘默认槽回到本包装。', '表填充实现未展开。'),
    '95c7d6': ('先977A09(1)初始化，再经A6AB74重试；磁盘默认槽回到本包装。', '表填充实现未展开。'),
    '977a09': ('首次复制284字节表，填充后依据配置和CPU功能选择分派；Type=0重置。',
               '注册表读取、CPU检测和三个表填充子实现未审；仅分派外层控制流已审。'),
    '637e20': ('先绕对象支点旋转12度并绘制，再按计时条件移动。', '仅图像消费片段；运动、计时状态未闭环。'),
    '7a3b00': ('间隔>1000ms且条件AL为0的分支调用缓存回收；末尾更新时间。', '分支的UI/文字处理及条件函数未审。'),
    '917330': ('从idguardlibr.dll模块资源加载按钮位图并赋字体；不是松散BMP游戏格式支持。',
               '字体与位图销毁、外部控件完整业务未闭环。'),
    '6daa10': ('十二名称前缀拆为类型0..11及atoi参数，交6DBA40；缺下划线/长度无防护。',
               '名称解析分支已审；6DBA40完整映射分配与输入可达性未在此证明。'),
}
REUSED = {
    '6dfa80': '有符号jl/jg分别拒绝<0及>30000；容量30000的边界不一致复核。',
    '813e70': '每调用最多推进一帧；就绪且+173非0才绘制；末尾+173=1；复核旧图像专题并补绘制门槛。',
}
BRIDGES = {'5ff055': 'E9到95E75E。', '6106e3': 'E9到95C7D6。'}


def main():
    entries = {}
    fingerprint = None
    for path in sorted((HERE / '证据').glob('*.json')):
        data = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(data, dict) or not isinstance(data.get('functions'), list):
            continue
        fingerprint = data['disk_sha256']
        for index, function in enumerate(data['functions']):
            key = function['va'][2:]
            entry = entries.setdefault(function['va'], dict(va=function['va'], evidence=[]))
            entry['evidence'].append(f'证据/{path.name}#/functions/{index}')
            if key in CONTRACTS:
                entry.update(status='静态契约已审阅', conclusion=CONTRACTS[key],
                             unknown='未实机执行；外部类型、并发调用和设备故障行为不由本条证明。')
            elif key in PARTIAL:
                conclusion, unknown = PARTIAL[key]
                entry.update(status='局部消费契约已审阅', conclusion=conclusion, unknown=unknown)
            elif key in REUSED:
                entry.update(status='既有专题审阅复核', conclusion=REUSED[key],
                             unknown='主审阅见图像资源专题；本专题绑定当前PE复核，不新增旧函数完成量。',
                             reused_review='../图像资源/01_图像索引与NP加载闭环.txt')
            elif key in BRIDGES:
                entry.update(status='跳板字节已核验', conclusion=BRIDGES[key], is_thunk=True,
                             unknown='只证明固定E9目标；跳板不计新增算法函数。')
            else:
                entry.update(status='邻近候选仅导出', conclusion='完整声明块导出，未登记语义结论。',
                             unknown='导出不等于分析完成。')
    rows = sorted(entries.values(), key=lambda row: int(row['va'], 16))
    result = dict(disk_sha256=fingerprint, scope='图像运行时局部接口；矩阵分派算法和外部UI保留边界',
                  functions=rows)
    (HERE / '函数审阅清单.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
    lines = ['// ============================================================================', '// 图像运行时 / 逐函数结论',
             '// ============================================================================', '// 原证指针见函数审阅清单.json；局部、复用、跳板独立计数。', '//']
    for row in rows:
        lines.extend(['// ' + row['va'].upper() + ' / ' + row['status'],
                      '//   ' + row['conclusion'], '//   未知：' + row['unknown'], '//'])
    (HERE / '05_逐函数结论.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8', newline='\n')
    print(len(rows))


if __name__ == '__main__':
    main()
