"""离线复算机器整数语义与映射基数；不运行客户端，不以仿真代替实机取样。"""
from pathlib import Path
from collections import Counter
import json

BASE=Path(__file__).resolve().parent
MASK=0xffffffff
def step(state):
    state=(state*214013+2531011)&MASK
    return state,(state>>16)&0x7fff
def split_step(state):
    # 以16位分块独立核对乘法低32位，不依赖宿主有符号溢出。
    low=(state&0xffff)*0x43fd
    high=(state>>16)*0x43fd+(state&0xffff)*3+(low>>16)
    state=((((high&0xffff)<<16)|(low&0xffff))+0x269ec3)&MASK
    return state,(state>>16)&0x7fff
def signed(v):
    v&=MASK
    return v-(1<<32) if v&(1<<31) else v
def idiv_remainder(dividend,divisor):
    if divisor==0:raise ZeroDivisionError('x86 IDIV除数0')
    q=abs(dividend)//abs(divisor)
    if (dividend<0)!=(divisor<0):q=-q
    if not -(1<<31)<=q<(1<<31):raise OverflowError('x86 IDIV商溢出')
    return dividend-q*divisor
def interval(a,b,r):
    n=signed(b-a+1)
    return signed(a+idiv_remainder(r,n))

vectors=[]
for seed in [0,1,0x7fffffff,0x80000000,0xffffffff,123456789]:
    s=seed
    values=[]
    states=[]
    for i in range(16):
        pair=step(s)
        assert pair==split_step(s)
        s,r=pair
        values.append(r)
        states.append(hex(s))
    vectors.append(dict(seed=hex(seed),outputs=values,states=states))
assert vectors[1]['outputs'][:5]==[41,18467,6334,26500,19169]
histograms=[]
for n in [1,6,16,62,601,1401,32768,32769]:
    counts=Counter(r%n for r in range(32768))
    q,k=divmod(32768,n)
    assert all(counts[i]==q+(i<k) for i in range(n))
    histograms.append(dict(modulus=n,source_cardinality=32768,quotient=q,remainder=k,
                           min_count=min(counts.get(i,0) for i in range(n)),
                           max_count=max(counts.values()),reachable=len(counts),
                           scope='枚举每个可能rand输出各一次；不是实机序列概率或独立性证明'))
boundaries=[]
for a,b in [(1,6),(10,10),(10,9),(10,8),(0,32767),(0,32768),(-2147483648,2147483647),(2147483647,2147483647)]:
    row=dict(a=a,b=b,width_signed=signed(b-a+1))
    try:
        values=[interval(a,b,r) for r in range(32768)]
        row.update(min=min(values),max=max(values),unique=len(set(values)),first=values[0],last=values[-1])
    except (ZeroDivisionError,OverflowError) as e:
        row['exception']=str(e)
    boundaries.append(row)
assert boundaries[2].get('exception')
assert boundaries[3]['min']==boundaries[3]['max']==10
assert boundaries[5]['max']==32767
alphabet=''.join(chr(r+97 if r<26 else r+39 if r<52 else r-4) for r in range(62))
assert alphabet=='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
assert signed(0xffff8000)==-32768
result=dict(scope='离线字节语义复算；没有运行EXE、没有生成协议权威随机数结论',
            lcg_vectors=vectors,modulo_support_histograms=histograms,interval_boundaries=boundaries,
            display_alphabet=alphabet,
            signed_short_examples=[dict(word=hex(v),result=v-0x10000 if v&0x8000 else v) for v in [0,32767,32768,65535]],
            reseed_example=dict(seed=1,first_output=41,after_reseed_first_output=41,
                                explanation='相同存储槽重置相同种子，第一项重复；其它调用若插入会消耗序列'))
(BASE/'simulation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(dict(vectors=len(vectors),steps=16*len(vectors),moduli=len(histograms),boundary_cases=len(boundaries)),ensure_ascii=True))
