"""七新种子及旧根无损适配；原字段、来源字段指针和字节块均保留。"""
import hashlib
import json
import runpy
from pathlib import Path

HERE=Path(__file__).resolve().parent
DOCS=HERE.parents[2]
SHA='a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
HELPER=DOCS/'专题/地图选择字段与列表消费/证据/adapt_sources.py'


def main():
    helper=runpy.run_path(str(HELPER));adapt=helper['adapt']
    path='专题/股票数值辅助与组合消费/证据/bounded_raw.json';raw=(DOCS/path).read_bytes();data=json.loads(raw)
    assert hashlib.sha256(raw).hexdigest()=='f3eaa46e1dbb7b7549a9c0779e65387ce4fee25a93a1baddc238ec44c0aa4c04'
    rows=[adapt(row,path,'/functions/'+str(i),hashlib.sha256(raw).hexdigest(),'本批新原证无损适配') for i,row in enumerate(data['functions'])]
    (HERE/'formal_functions.json').write_text(json.dumps(dict(disk_sha256=SHA,adapter_helper_sha256=hashlib.sha256(HELPER.read_bytes()).hexdigest(),functions=rows),ensure_ascii=False,indent=2)+'\n','utf-8')
    path='专题/股票与交易流程/证据/stock_core.json';raw=(DOCS/path).read_bytes();data=json.loads(raw)
    row=data['functions'][2];assert row['va']=='0x6283e0'
    rows=[adapt(row,path,'/functions/2',hashlib.sha256(raw).hexdigest(),'旧根局部契约复用')]
    path='专题/高扇入界面操作辅助/证据/dependency_raw.json';raw=(DOCS/path).read_bytes();data=json.loads(raw)
    row=data['functions'][2];assert row['va']=='0x922798'
    rows.append(adapt(row,path,'/functions/2',hashlib.sha256(raw).hexdigest(),'既有运行库窄转换契约复用'))
    (HERE/'reused_functions.json').write_text(json.dumps(dict(disk_sha256=SHA,functions=rows),ensure_ascii=False,indent=2)+'\n','utf-8')
    print('adapted 7 new seeds, historical root and narrow conversion contracts')


if __name__=='__main__':
    main()
