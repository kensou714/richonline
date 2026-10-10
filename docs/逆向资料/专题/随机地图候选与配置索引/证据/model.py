"""局部算法模型；不模拟资源加载、全局对象或真实客户端。"""
from collections import Counter
from itertools import product

ALLOWED = {0: {0,3}, 1: {0,1,3}, 2: {0,1,2,3}, 3: {3}}

def allow(threshold, category):
    return category in ALLOWED.get(threshold, set())

def select(start, accepted):
    assert accepted and 0 <= start < len(accepted), '模型拒绝原函数未保护的非法输入'
    visited = []
    for step in range(len(accepted)):
        position = (start+step) % len(accepted)
        visited.append(position)
        if accepted[position]:
            return position, visited
    return None, visited

def verify():
    checks = 0
    for count in range(1,10):
        for bits in product([False,True], repeat=count):
            for start in range(count):
                chosen, visited = select(start,bits)
                oracle = next((i for i in list(range(start,count))+list(range(start)) if bits[i]),None)
                assert chosen == oracle
                assert len(visited) <= count and len(set(visited)) == len(visited)
                assert len(visited) == count if not any(bits) else bits[chosen]
                checks += 1
    histogram = Counter(select(i,[True,False,False,True])[0] for i in range(4))
    assert histogram == {0:1,3:3}
    modulo = {n: dict(Counter(x % n for x in range(32768))) for n in [3,4,9,16,22,25,26]}
    for n, values in modulo.items():
        assert max(values.values())-min(values.values()) <= 1
        assert sum(values.values()) == 32768 and len(values)==n
    matrix = [dict(threshold=t,category=c,accepted=allow(t,c)) for t in [-1,0,1,2,3,4,0xFFFFFFFF] for c in [-1,0,1,2,3,4]]
    return dict(selection_cases=checks, threshold_cases=matrix, rejection_bias_example=dict(histogram),
                modulo_histograms=modulo, invalid_inputs='空列表和越界起点不执行模型；真实入口缺局部保护')

if __name__ == '__main__':
    from pathlib import Path
    import json
    result=verify()
    (Path(__file__).resolve().parent/'model_results.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(result['selection_cases'])
