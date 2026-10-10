"""图像尺寸状态局部模型；回调不重入、不修改索引是模型前提。"""
from itertools import product
from collections import Counter
from pathlib import Path
import json

def update(kind,state,image_id,path,dimensions,builtin,callback):
    cache=(900,901)
    events=[]
    dimensions=tuple(dimensions)
    if kind==5 and state==1:
        if image_id>=0 or path:
            if dimensions==(0,0):
                if callback=='missing':
                    return dict(state=state,dimensions=dimensions,cache=cache,events=['missing'])
                events.append('id' if image_id>=0 else 'path')
                if callback=='false':
                    return dict(state=state,dimensions=(0,0),cache=cache,events=events+['failed'])
                dimensions=(-1,-1) if callback=='true-invalid' else (320,240)
            if builtin:
                cache=dimensions
    return dict(state=state,dimensions=dimensions,cache=cache,events=events)

def refresh_gate(enabled,visible,index):
    return bool(visible) and ((bool(enabled) and index==0) or (not enabled and index==3))

def verify():
    cases=[]
    for kind,state,image_id,path,dimensions,builtin,callback in product(
        [0,5],[-1,0,1,2],[-1,0],['','file'],[(0,0),(1,0),(0,1),(-1,-1)],
        [False,True],['missing','false','true','true-invalid']):
        actual=update(kind,state,image_id,path,dimensions,builtin,callback)
        # 独立判据核对是否调用/镜像；失败不把活动尺寸清零。
        ready=kind==5 and state==1 and (image_id>=0 or bool(path))
        called=ready and dimensions==(0,0) and callback!='missing'
        assert any(e in ['id','path'] for e in actual['events'])==called
        mirrored=ready and builtin and (dimensions!=(0,0) or callback in ['true','true-invalid'])
        assert (actual['cache']!=(900,901))==mirrored
        assert actual['state']==state
        if not ready:assert actual['dimensions']==dimensions and not actual['events']
        if called and callback=='false':assert actual['dimensions']==(0,0) and actual['cache']==(900,901)
        cases.append(actual)
    gates=[]
    for enabled,visible,index in product([0,1,2],[0,1,2],[-1,0,1,2,3,4]):
        result=refresh_gate(enabled,visible,index)
        assert result==(visible!=0 and index==(0 if enabled else 3))
        gates.append(dict(enabled=enabled,visible=visible,index=index,refresh=result))
    return dict(state_cases=len(cases),event_counts=dict(Counter(e for c in cases for e in c['events'])),
                refresh_cases=gates,false_callback_example=update(5,1,0,'',(0,0),True,'false'),
                true_invalid_example=update(5,1,0,'',(0,0),True,'true-invalid'),
                cached_invalid_example=update(5,1,0,'',(-1,-1),True,'true'),
                caveat='合法索引、存储有效、回调不重入/不改索引；不模拟分配与字符串释放')

if __name__=='__main__':
    result=verify()
    (Path(__file__).resolve().parent/'model_results.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(result['state_cases'])
