"""从冻结旧loader逐站截取原指令，核当前磁盘并绑定十二文件分类。"""
import json
import runpy
import struct
from pathlib import Path

HERE=Path(__file__).resolve().parent
A=runpy.run_path(str(HERE/'author.py'))
SPECS=[
 ('road.dat',0x6D8283,0x6D84DB,0x6D84F8,0x6D8539,0x3ABB0,[180,12],'正常R_g_S_i；i<15'),
 ('road.dat',0x6D8283,0x6D8595,0x6D85B2,0x6D8615,0x3ABB0,[180,12],'i为11/12时派生到i+2，+8=i-11'),
 ('thing.dat',0x6D8631,0x6D8851,0x6D8865,0x6D888E,0x3ABB8,[12],'THING_i单项'),
 ('event.dat',0x6D88A5,0x6D8AF4,0x6D8B0E,0x6D8B49,0x3ABC0,[120,12],'E_g_S_i；i<10'),
 ('build.dat',0x6D8B65,0x6D8DF6,0x6D8E1D,0x6D8E6E,0x3ABC8,[1200,120,12],'B_g_L_l_F_f；l<10、f<10'),
 ('vehicle.dat',0x6D8E8F,0x6D9120,0x6D9147,0x6D9198,0x3ABD0,[480,120,12],'V_g_D_d_F_f；d<4、f<10'),
 ('vehicle.dat',0x6D8E8F,0x6D9200,0x6D9227,0x6D92A2,0x3ABD0,[480,120,12],'d为1时派生到d=3，+8=0'),
 ('role.dat',0x6D92C3,0x6D9557,0x6D9581,0x6D95D8,0x3ABD8,[4800,1200,12],'R_g_D_d_F_f；d<4、f<100'),
 ('role.dat',0x6D92C3,0x6D9646,0x6D9670,0x6D96F4,0x3ABD8,[4800,1200,12],'d为1时派生到d=3，+8=0'),
 ('npc.dat',0x6D9715,0x6D996D,0x6D998A,0x6D99CB,0x3ABE0,[1200,12],'N_g_S_i；i<100'),
 ('fx.dat',0x6D99E7,0x6D9C07,0x6D9C1B,0x6D9C44,0x3ABE8,[12],'FX_i单项'),
 ('mood.dat',0x6D9C5B,0x6D9EB3,0x6D9ED0,0x6D9F11,0x3ABF0,[1200,12],'M_g_S_i；i<100'),
 ('card.dat',0x6D9F2D,0x6DA14D,0x6DA161,0x6DA18A,0x3ABF8,[12],'CARD_i单项'),
 ('other.dat',0x6DA1A1,0x6DA3F9,0x6DA416,0x6DA457,0x3AC00,[1200,12],'O_g_S_i；i<100'),
 ('extend.dat',0x6DA473,0x6DA693,0x6DA6A7,0x6DA6D0,0x3AC08,[12],'EXTEND_i单项'),
]


def inspect():
    img=A['Image']();path='专题/4019系列事件/证据/resource_loader_scope.json';data=A['read'](A['DOCS']/path)
    f=data['functions'][0];asm=f['assembly'];byva={int(a['va'],16):i for i,a in enumerate(asm)}
    rows=[]
    for filename,file_site,pop,write,register,field,strides,scope in SPECS:
        index=byva[pop];end=byva[register]
        assert asm[index-2]['text']=='mov     ecx, [ebp+Destination]'
        assert asm[index-1]['text']=="add     ecx, 40h ; '@'"
        assert asm[index]['text']=='call    sub_601896'
        assert '+4], eax' in asm[byva[write]]['text']
        assert '580CCh]' in asm[end]['text']
        selected=[]
        for i in range(index-2,end+1):
            a=asm[i];v=int(a['va'],16);stop=int(asm[i+1]['va'],16)
            selected.append(dict(source_pointer='/functions/0/assembly/'+str(i),original=a,
                                 disk_hex=img.disk(v,stop-v).hex(),decoded=img.ins(v,stop-v)))
        joined='\n'.join(x['decoded'] for x in selected)
        assert hex(field) in joined
        for stride in strides:assert hex(stride) in joined
        raw=img.disk(file_site,5);assert raw[0]==0x68
        target=struct.unpack_from('<I',raw,1)[0];namebytes=filename.encode()+b'\0';assert img.disk(target,len(namebytes))==namebytes
        rows.append(dict(file=filename,file_push_va=hex(file_site),filename_target_va=hex(target),filename_hex=namebytes.hex(),
                         filename_evidence='旧loader压栈指令+当前磁盘精确首NUL观察；不是本批IDA字符串声明',
                         pop_va=hex(pop),slot_write_va=hex(write),register_va=hex(register),array_member=hex(field),strides=strides,
                         reading_scope=scope,source_path=path,source_sha256=A['sha']((A['DOCS']/path).read_bytes()),instructions=selected))
    calls=[int(c['site'],16) for c in f['calls'] if c.get('implementation')=='0x6d7660']
    assert calls==[x[2] for x in SPECS]
    return dict(status='PASS',sites=rows,site_count=15,file_categories=12,
                scope='仅旧完整loader的15取槽/登记站；未宣称全部动态间接取槽路径穷举')


def main():
    result=inspect();A['put'](HERE/'shared_sites.json',result)
    print('15 shared-pool sites / 12 file categories PASS')


if __name__=='__main__':main()
