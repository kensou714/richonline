"""第28批作者适配：新主体、旧来源补核、有限调用窗口分层。"""
import hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
DOCS=HERE.parents[2]
RAW_SHA='73c4b8febe7b40beed41ab6602dde5dbd8a27fc66dbc79a807686dc8ec23d490'
REUSE=(('专题/角色1416字段来源/证据/functions.json','/functions/18'),('专题/随机地图候选与配置索引/证据/functions_raw.json','/functions/6'),('专题/录像文件与执行链/证据/io_and_parser_navigation.json','/functions/21'),('专题/地图与路径/证据/map_runtime_core.json','/函数/2'))
HELPERS=(('专题/随机地图候选与配置索引/证据/dependencies_raw.json','/functions/0'),('专题/随机地图候选与配置索引/证据/dependencies_raw.json','/functions/1'),('专题/随机地图候选与配置索引/证据/dependencies_raw.json','/functions/8'),('专题/地图与路径/证据/map_runtime_core.json','/函数/74'),('专题/地图与路径/证据/map_runtime_core.json','/函数/0'),('专题/名称查找与等待消费者/证据/supplement_formal.json','/functions/2'),('专题/大厅URL读取与缓冲契约/证据/short_helpers_raw.json','/functions/8'))
def digest(b):return hashlib.sha256(b).hexdigest()
def bind(path,pointer):
 b=(DOCS/path).read_bytes();n=json.loads(b)
 for k in pointer.strip('/').split('/'):n=n[int(k)] if isinstance(n,list) else n[k]
 return {'base':'docs','path':path,'sha256':digest(b),'json_pointer':pointer},n
def build():
 raw=json.loads((HERE/'bounded_raw.json').read_bytes());assert digest((HERE/'bounded_raw.json').read_bytes())==RAW_SHA
 funcs=[]
 for i,f in enumerate(raw['functions']):
  funcs.append(dict(va=f['seed_va'],end_va=f['end_va'],name=f['name'],source={'base':'topic','path':'证据/bounded_raw.json','sha256':digest((HERE/'bounded_raw.json').read_bytes()),'json_pointer':f'/functions/{i}'},source_record=f,pseudocode=f['pseudocode'],assembly=[dict(va=x['site_va'],text=x['text'],is_code=x['is_code']) for x in f['assembly']],chunk_byte_ranges=f['chunk_byte_ranges'],coverage_origin='本批新增完整主体'))
 legacy=[]
 for i,(path,pointer) in enumerate(REUSE):
  source,node=bind(path,pointer); audit=raw['reused_source_byte_audits'][i]
  legacy.append(dict(va=audit['seed_va'],source=source,source_record_json=json.dumps(node,ensure_ascii=False,separators=(',',':')),source_status=node.get('status',node.get('状态')),source_audits=audit['current_byte_audits'],scope='旧原证补核；不计本批新增'))
 helpers=[]
 for path,pointer in HELPERS:
  source,node=bind(path,pointer)
  helpers.append(dict(va=node.get('va',node.get('地址')),source=source,source_record_json=json.dumps(node,ensure_ascii=False,separators=(',',':')),scope='旧契约有限复用及当前PE核验；不新增IDA导出或完整函数认领'))
 boundary=(HERE/'boundary_data/bounded_raw.json').read_bytes()
 result=dict(schema='richonline-shared-map-callback-formal-1',disk_sha256=raw['disk_sha256'],raw_sha256=RAW_SHA,functions=funcs,legacy_reused_functions=legacy,helper_contracts=helpers,caller_windows=raw['explicit_owner_windows'],bridges=raw['verified_direct_bridges'],calls=raw['calls'],boundary_data_sha256=digest(boundary),coverage_origin='2个新增主体；4个旧主体仅补当前PE字节')
 (HERE/'formal_functions.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
 print(json.dumps({'functions':2,'legacy':4,'windows':len(raw['explicit_owner_windows']),'raw_sha256':RAW_SHA},ensure_ascii=False))
if __name__=='__main__':build()
