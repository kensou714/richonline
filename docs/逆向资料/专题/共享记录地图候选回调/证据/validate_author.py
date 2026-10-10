"""当前PE字节、无损源绑定、完整主体与ABI锚；不连接IDA，不运行客户端。"""
import json,struct
from pathlib import Path
import capstone
from build_formal import HERE,DOCS,RAW_SHA,REUSE,HELPERS,bind,digest
ROOT=DOCS.parents[1]
EXPECTED='a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
DOCS_NAMES=('00_有限采证实施计划.txt','01_共享记录遍历与回调ABI.txt','02_字符串摘要读取与失败边界.txt','03_来源分层与复核边界.txt')
def validate():
 image=(ROOT/'RnClient.exe').read_bytes();assert digest(image)==EXPECTED
 pe=struct.unpack_from('<I',image,60)[0];base=struct.unpack_from('<I',image,pe+52)[0]
 table=pe+24+struct.unpack_from('<H',image,pe+20)[0]
 secs=[struct.unpack_from('<4I',image,table+40*i+8) for i in range(struct.unpack_from('<H',image,pe+6)[0])]
 def read(va,n):
  offsets=[off+va-base-rva for _,rva,size,off in secs if rva<=va-base and va-base+n<=rva+size]
  assert len(offsets)==1;return image[offsets[0]:offsets[0]+n]
 md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);md.detail=True
 decoded={};ranges=set();nrecords=0
 def audit(va,b):
  nonlocal nrecords
  assert b==read(va,len(b));ranges.add((va,len(b)));nrecords+=1
 def decode(va,b):
  audit(va,b);ins=list(md.disasm(b,va));assert sum(i.size for i in ins)==len(b)
  for i in ins:
   if i.address in decoded:assert decoded[i.address].bytes==i.bytes
   decoded[i.address]=i
  return ins
 def blocks(bs):
  out=[]
  for b in bs:
   blob=bytes.fromhex(b['idb_hex']);assert blob.hex()==b['disk_hex'] and b['matching'] and len(blob)==b['size']
   if b.get('sha256'):assert digest(blob)==b['sha256']
   out+=decode(int(b.get('start_va',b.get('va')),16),blob)
  return out
 raw=json.loads((HERE/'bounded_raw.json').read_bytes());formal=json.loads((HERE/'formal_functions.json').read_bytes())
 assert digest((HERE/'bounded_raw.json').read_bytes())==RAW_SHA==formal['raw_sha256']
 assert raw['disk_sha256']==formal['disk_sha256']==EXPECTED
 assert raw['prepared_wrapper_sha256']==digest((HERE/'export_bounded.py').read_bytes())
 assert len(raw['functions'])==2 and not raw['reused_seeds'] and not raw['data_windows']
 def record(f):
  source,node=bind(f['source']['path'],f['source']['json_pointer']);assert source==f['source']
  assert 'source_record' not in f and isinstance(f['source_record_json'],str)
  assert json.loads(f['source_record_json'])==node
  return node
 def old_decode(node):
  if '完整汇编' in node:
   out=[]
   for row in node['完整汇编']:
    b=row['字节核验'];assert b['匹配'] and b['IDB字节']==b['磁盘字节']
    ins=decode(int(row['地址'],16),bytes.fromhex(b['IDB字节']));assert len(ins)==1;out+=ins
  else:
   out=blocks(node.get('chunk_byte_ranges') or node['byte_ranges'])
   assert {i.address for i in out}=={int(r['va'],16) for r in node['assembly']}
  return out
 subjects=[]
 for i,f in enumerate(formal['functions']):
  original=raw['functions'][i];assert f['source_record']==original and f['va']==original['seed_va']
  assert f['pseudocode']==original['pseudocode'] and f['chunk_byte_ranges']==original['chunk_byte_ranges']==raw['current_chunk_audits'][i]['chunk_byte_ranges']
  assert f['source']['sha256']==RAW_SHA and f['source']['json_pointer']==f'/functions/{i}'
  ins=blocks(f['chunk_byte_ranges']);assert [hex(x.address) for x in ins]==[r['site_va'] for r in original['assembly']]
  assert f['assembly']==[dict(va=r['site_va'],text=r['text'],is_code=r['is_code']) for r in original['assembly']]
  assert ins[-1].address+ins[-1].size==int(f['end_va'],16)
  subjects.append(dict(va=f['va'],bytes=sum(x.size for x in ins),instructions=len(ins)))
 assert [(x['bytes'],x['instructions']) for x in subjects]==[(128,45),(60,23)]
 legacy=[]
 for i,f in enumerate(formal['legacy_reused_functions']):
  node=record(f);ins=old_decode(node);a=raw['reused_source_byte_audits'][i]
  assert f['source']['sha256']==a['source_sha256'] and f['source']['path']==a['source_path'] and f['source']['json_pointer']==a['source_pointer']
  assert f['source_audits']==a['current_byte_audits'] and f['va']==a['seed_va']
  for b in a['current_byte_audits']:
   at=int(b['start_va'],16);blob=bytes.fromhex(b['current_idb_hex']);assert blob.hex()==b['current_disk_hex'] and len(blob)==b['size'] and b['matching'] and digest(blob)==b['sha256'];audit(at,blob)
  legacy.append(dict(va=f['va'],instructions=len(ins),bytes=sum(x.size for x in ins)))
 assert sum(x['bytes'] for x in legacy)==1516 and sum(x['instructions'] for x in legacy)==463
 helpers=[]
 for f in formal['helper_contracts']:
  node=record(f);ins=old_decode(node);helpers.append(dict(va=f['va'],instructions=len(ins),bytes=sum(x.size for x in ins)))
 assert len(helpers)==len(HELPERS)==7
 def bridge(va):
  b=read(va,5);assert b[0]==0xE9;return va+5+struct.unpack_from('<i',b,1)[0]
 for b in raw['verified_direct_bridges']:
  blocks([b]);assert bridge(int(b['start_va'],16))==int(b['target_va'],16)
 assert len(raw['verified_direct_bridges'])==4
 calls={}
 for f in formal['functions']:
  lo=int(f['va'],16);hi=int(f['end_va'],16)
  for a,i in decoded.items():
   if lo<=a<hi and i.mnemonic=='call' and i.operands[0].type==capstone.x86.X86_OP_IMM:calls[(f['va'],hex(a))]=hex(i.operands[0].imm)
 assert calls=={(c['seed_va'],c['site_va']):c['target_va'] for c in raw['calls']}
 for c in raw['calls']:
  va=int(c['target_va'],16)
  for hop in c['bridges']:assert va==int(hop,16);va=bridge(va)
  assert va==int(c['implementation_va'],16)
 nav={}
 def window(w):
  k=(w['owner_va'],w['site_va'])
  if k in nav:assert nav[k]==w['assembly']
  nav[k]=w['assembly']
  for row in w['assembly']:
   ins=blocks([row['bytes']]);assert len(ins)==1 and hex(ins[0].address)==row['site_va']
 assert formal['caller_windows']==raw['explicit_owner_windows']
 for w in raw['explicit_owner_windows']:window(w)
 for entries in raw['incoming'].values():
  for e in entries:
   if e.get('owner_window'):window(e['owner_window'])
 assert len(raw['explicit_owner_windows'])==12
 boundary=json.loads((HERE/'boundary_data/bounded_raw.json').read_bytes())
 assert formal['boundary_data_sha256']==digest((HERE/'boundary_data/bounded_raw.json').read_bytes())
 for b in boundary['data_windows']:
  payload=bytes.fromhex(b['idb_hex']);assert payload.hex()==b['disk_hex'] and b['matching'];audit(int(b['start_va'],16),payload)
 assert len(boundary['data_windows'])==6 and sum(b['size'] for b in boundary['data_windows'])==60
 assert struct.unpack('<4I',read(0x6AAB34,16))==(0x6AAADC,0x6AAAEE,0x6AAB06,0x6AAAD0)
 assert struct.unpack('<2I',read(0x7E727A,8))==(1,0x7E7282)
 assert struct.unpack('<iII',read(0x7E7282,12))==(-76,64,0x7E728E)
 assert read(0x7E728E,14)==b'szFullMapName\0' and read(0xA2D950,7)==b'Map\\%s\0' and read(0xA2D970,3)==b'rb\0'
 anchors={0x6BA188:('cmp','dword ptr [ebp + 8], 0'),0x6BA191:('cmp','dword ptr [eax], 0'),0x6BA199:('cmp','dword ptr [ecx + 4], 0'),0x6BA1B7:('call','dword ptr [ebp + 8]'),0x6BA1BA:('add','esp, 8'),0x6BA1C4:('test','eax, eax'),0x6BA1C8:('mov','eax, 1'),0x6BA1D2:('mov','ecx, dword ptr [eax + 0x80]'),0x6BA1DD:('xor','eax, eax'),0x6BA1ED:('ret','8'),0x6AAA4B:('mov','eax, dword ptr [ebp + 0xc]'),0x6AAA51:('mov','ecx, dword ptr [ebp + 8]'),0x6AAA54:('push','ecx'),0x6AAA58:('push','edx'),0x6AAA61:('test','eax, eax'),0x6AAA65:('mov','eax, 1'),0x6AAA6C:('xor','eax, eax'),0x6AAA7B:('ret',''),0x7E722B:('push','1'),0x7E722D:('push','0x10'),0x7E7232:('add','ecx, 8'),0x7E724D:('add','eax, 8'),0x6A58BB:('cmp','dword ptr [ebp - 0x5ec], 0x10')}
 for at,want in anchors.items():
  i=decoded[at];assert (i.mnemonic,i.op_str)==want,(hex(at),i.mnemonic,i.op_str,want)
 sites=(0x6A55A3,0x6A55EB,0x6A5633,0x6A567B,0x6A56C3,0x6A570B,0x6A5753,0x6A579B,0x6A57E3,0x6A582B)
 offsets=(0x514,0x520,0x524,0x528,0x52C,0x530,0x534,0x538,0x53C,0x540)
 for at,off in zip(sites,offsets):
  assert decoded[at-6].op_str==f'ecx, dword ptr [edx + {hex(off)}]'
  assert decoded[at+5].mnemonic=='test' and decoded[at+5].op_str=='eax, eax'
  assert decoded[at+21].mnemonic=='movzx' and decoded[at+21].op_str=='ecx, al'
 # 数值模型只解释已核分支；不替代回调或CRT实机执行。
 def search(callback,head,gate,chain,values):
  seen=[]
  if not callback or not head or not gate:return 0,seen
  while head:
   seen.append(head)
   if values[head]&0xFFFFFFFF:return 1,seen
   head=chain[head]
  return 0,seen
 cases=[(0,1,1,{1:0},{1:1},(0,[])),(1,0,1,{}, {},(0,[])),(1,1,0,{1:0},{1:1},(0,[])),(1,1,1,{1:2,2:0},{1:0,2:256},(1,[1,2])),(1,1,1,{1:2,2:0},{1:-1,2:0},(1,[1])),(1,1,1,{1:2,2:0},{1:0,2:0},(0,[1,2]))]
 for c,h,g,chain,vals,expected in cases:assert search(c,h,g,chain,vals)==expected
 compare=[(bytes(16),bytes(16),True)]+[(bytes(16),bytes([0]*i+[1]+[0]*(15-i)),False) for i in range(16)]
 assert all((a==b)==want for a,b,want in compare)
 manifest=json.loads((HERE.parent/'函数审阅清单.json').read_bytes())
 assert len(manifest['functions'])==6 and len(manifest['legacy_reused'])==4 and len(manifest['windows'])==12
 def review_hits(n):
  if isinstance(n,dict):
   if any(k in n for k in ('va','address','ea','地址')) and isinstance(n.get('status',n.get('review_status',n.get('状态'))),str) and isinstance(n.get('conclusion',n.get('结论')),str):yield n
   for v in n.values():yield from review_hits(v)
  elif isinstance(n,list):
   for v in n:yield from review_hits(v)
 assert not list(review_hits(formal)) and len(list(review_hits(manifest)))==6
 for name in DOCS_NAMES:assert all(not line.strip() or line.startswith('//') for line in (HERE.parent/name).read_text(encoding='utf8').splitlines())
 paths=[HERE.parent/n for n in DOCS_NAMES]+[HERE.parent/'函数审阅清单.json']+[HERE/n for n in ('bounded_raw.json','formal_functions.json','export_bounded.py','build_formal.py','build_review.py','validate_author.py','export_boundary_data.py','boundary_data/bounded_raw.json')]
 return dict(status='PASS',scope='静态字节/来源/ABI核验与说明模型；不证明实机文件失败后必达比较',subjects=subjects,legacy=legacy,helpers=helpers,byte_records=nrecords,unique_byte_ranges=len(ranges),navigation_windows=len(nav),anchors=len(anchors),direct_calls=4,indirect_calls=1,ida_bridges=4,data_windows=6,data_bytes=60,models={'search':len(cases),'compare16':len(compare)},final_binding_sha256={p.relative_to(HERE.parent).as_posix():digest(p.read_bytes()) for p in paths})
if __name__=='__main__':
 r=validate();(HERE/'author_validation.json').write_text(json.dumps(r,ensure_ascii=False,indent=2)+'\n',encoding='utf8');print(json.dumps({k:r[k] for k in ('status','subjects','byte_records','unique_byte_ranges','anchors')},ensure_ascii=False))
