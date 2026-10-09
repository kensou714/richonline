"""复现局部字节算法；不执行 EXE，不模拟网络及界面可达性。"""
from pathlib import Path
from collections import Counter
import json

BASE=Path(__file__).resolve().parent
def load(n):return json.loads((BASE/n).read_text('utf-8'))
table=(BASE/'ChsTb.kpd.decoded.bin').read_bytes()
def mapped(pair,reverse=False):
    hi,lo=pair
    at=(0x7fc8+(hi-0xa1)*764+(lo-0x40)*4) if reverse else ((hi-0xa1)*376+(lo-0xa1)*4)
    if at<0 or at+4>len(table):return None
    return table[at+2:at+4]
examples=[]
for text in ['中国','汉语','台湾','游戏','音乐','后发']:
    src=text.encode('gb2312')
    dst=b''.join(mapped(src[i:i+2]) for i in range(0,len(src),2))
    back=b''.join(mapped(dst[i:i+2],True) for i in range(0,len(dst),2))
    examples.append(dict(input=text,source_hex=src.hex(),target_hex=dst.hex(),
                         target_cp950=dst.decode('cp950'),back_hex=back.hex(),roundtrip=back==src))
def filtering(data,words,limit=100):
    buf=bytearray(data);p=0;hit=False;steps=[]
    for _ in range(limit):
        if p>=len(buf):return dict(output=buf.hex(),status='读过已提供缓冲区',steps=steps,changed=hit)
        if buf[p]==0:return dict(output=buf.hex(),status='到达零终止',steps=steps,changed=hit)
        step=1+(buf[p]>=128);which=None
        for idx,w in enumerate(words):
            if bytes(buf[p:p+len(w)])==w:
                buf[p:p+len(w)]=b'*'*len(w);step=len(w);hit=True;which=idx;break
        steps.append(dict(offset=p,advance=step,word=which))
        if step==0:return dict(output=buf.hex(),status='零长度命中导致不前进',steps=steps,changed=hit)
        p+=step
    raise AssertionError('模型步数不够')
cases=[]
for title,data,words in [
    ('顺序短词优先',b'abc\0',[b'ab',b'abc']),
    ('顺序长词优先',b'abc\0',[b'abc',b'ab']),
    ('区分大小写',b'Abc\0',[b'abc']),
    ('空词条',b'x\0',[b'']),
    ('尾部孤立高位字节',b'\x81\0',[]),
    ('不从双字节第二字节起配',b'\x81ab\0',[b'ab']),
    ('短输入不会按长词覆盖',b'ab\0',[b'abcd'])]:
    cases.append(dict(title=title,input_hex=data.hex(),words=[w.hex() for w in words],result=filtering(data,words)))
surveys=[]
for t,codec in zip(load('resources.json')[-1]['tables'],['gb2312','cp950']):
    valid=0;back_equal=0;target_decode=0
    target_codec='cp950' if codec=='gb2312' else 'gb2312'
    for e in t['entries']:
        src=bytes.fromhex(e['source']);dst=bytes.fromhex(e['target'])
        try:src.decode(codec);valid+=1
        except UnicodeError:continue
        try:dst.decode(target_codec);target_decode+=1
        except UnicodeError:pass
        rev=mapped(dst,codec=='gb2312') if all(v>=0x40 for v in dst) else None
        if rev==src:back_equal+=1
    surveys.append(dict(direction=t['name'],records=len(t['entries']),source_grid_matches=t['source_matches_grid'],
                         zero_targets=t['zero_targets'],question_targets=t['question_targets'],
                         source_codec=codec,source_decode_success=valid,target_codec=target_codec,
                         target_decode_success=target_decode,table_lookup_roundtrip_equal=back_equal,
                         note='往返只查表，未套用入口范围判定；不能据此宣称全部输入可运行转换'))
out=dict(mapping_examples=examples,filter_cases=cases,table_surveys=surveys)
(BASE/'simulation.json').write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(out,ensure_ascii=True))
