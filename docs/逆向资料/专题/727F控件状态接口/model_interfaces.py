"""机器整数宽度与存储生命周期的有限模型，不调用客户端或Windows转换API。"""
import struct

MASK=0xFFFFFFFF


def u32(value):
    return value & MASK


def i32(value):
    value=u32(value)
    return value-(1<<32) if value&0x80000000 else value


def counter_address(base,row,col):
    return u32(base+3744+u32(row*10000)+u32(col*2))


def increment(value,col):
    return (value+1)&0xFFFF,u32(col)


def line_pointer_address(base,index,count):
    return None if i32(index)>=i32(count) else u32(base+u32(index*160)+8)


def check_model():
    for value in range(65536):
        stored,returned=increment(value,-7)
        assert stored==((value+1)%65536) and returned==0xFFFFFFF9
    values=(-0x80000000,-5001,-1,0,1,4999,5000,65535,0x7FFFFFFF,0xFFFFFFFF)
    count_cases=0
    for base in (0,0x10000000,0xFFFFFF00):
        for row in values:
            for col in values:
                assert counter_address(base,row,col)==(base+3744+row*10000+col*2)%(1<<32)
                count_cases+=1
        assert counter_address(base,0,5000)==counter_address(base,1,0)
    line_cases=0
    for index in values:
        for count in values:
            address=line_pointer_address(0x100000,index,count)
            if i32(index)>=i32(count):
                assert address is None
            else:
                assert address==(0x100008+i32(index)*160)%(1<<32)
            line_cases+=1
    assert line_pointer_address(0x100000,-1,3)==0xFFF68
    predicate_cases=0
    for field in values:
        assert (u32(field)!=MASK)==(i32(field)!=-1)
        predicate_cases+=1
    stack_cases=0
    for entry_sp in (0x10000,0x12345000,0x7FFEF000):
        current=entry_sp-0x104-8
        callback_return=current+8
        default_return=(current+4)+4
        assert callback_return==default_return==entry_sp-260
        after_epilogue=current+8+0x104+4
        assert after_epilogue==entry_sp+4
        assert callback_return<entry_sp and callback_return+260==entry_sp
        stack_cases+=1
    # 有界临时区内仅以几何不等式验证空间，不能替代原函数的缺失检查。
    concat_cases=0
    for prefix in (0,1,512,10239,10240):
        for insert in (0,1,260,10239,10240):
            for suffix in (0,1,512,10239,10240):
                total=prefix+insert+suffix
                has_terminator=total<10240
                overflow=total>10240
                assert has_terminator==(total+1<=10240)
                assert not(has_terminator and overflow)
                concat_cases+=1
    float_cases=0
    for bits in (0,0x80000000,0x3F800000,0xBF800000,0x7F800000,0xFF800000):
        value=struct.unpack('<f',struct.pack('<I',bits))[0]
        assert struct.pack('<f',value)==struct.pack('<I',bits)
        float_cases+=1
    return dict(word_increment_cases=65536,address_cases=count_cases,negative_and_upper_index_cases=line_cases,
                record_predicate_cases=predicate_cases,stack_epilogue_cases=stack_cases,
                concatenation_capacity_cases=concat_cases,float_storage_cases=float_cases,
                limitation='有限整数/地址/容量模型；不访问非法地址，不模拟Win32编码、x87异常、回调或真实编辑器。')


if __name__=='__main__':
    import json
    print(json.dumps(check_model(),ensure_ascii=False))
