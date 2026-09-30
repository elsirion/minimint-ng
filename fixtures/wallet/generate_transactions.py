"""Spec-calculated Wallet transaction fixture, independent of Rust code.
Python struct/hashlib encodes bytes; OpenSSL public EC arithmetic builds scripts.
No Bitcoin Core acceptance or baseline comparison is claimed.
"""
import hashlib,json,struct
from pathlib import Path
import generate_filter_fixture as ec
H=lambda b:hashlib.sha256(b).digest()
D=lambda b:H(H(b))
le32=lambda n:struct.pack('<I',n)
le64=lambda n:struct.pack('<Q',n)
def size(n):
    if n<253:return bytes([n])
    if n<=65535:return b'\xfd'+struct.pack('<H',n)
    if n<=4294967295:return b'\xfe'+le32(n)
    return b'\xff'+le64(n)
def big(n):
    if n<253:return bytes([n])
    if n<=65535:return b'\xfd'+struct.pack('>H',n)
    if n<=4294967295:return b'\xfe'+struct.pack('>I',n)
    return b'\xff'+struct.pack('>Q',n)
def witness(tweak):
    ec.point_mul(ec.tweak_point,int.from_bytes(tweak,'big'))
    keys=[]
    for key in ec.keys:
        assert ec.add(ec.group,ec.result,key,ec.tweak_point,ec.ctx)==1
        keys.append(ec.public(ec.result))
    return b'\x53'+b''.join(b'\x21'+k for k in sorted(keys))+b'\x54\xae'
def output(value,script):return le64(value)+size(len(script))+script
def transaction(inputs,outputs,sequence=0xfffffffd):
    return le32(2)+size(len(inputs))+b''.join(p+b'\0'+le32(sequence) for p in inputs)+size(len(outputs))+b''.join(output(*o) for o in outputs)+le32(0)
def sighash(inputs,outputs,index,script,value):
    return D(le32(2)+D(b''.join(inputs))+D(le32(0xfffffffd)*len(inputs))+inputs[index]+size(len(script))+script+le64(value)+le32(0xfffffffd)+D(b''.join(output(*o) for o in outputs))+le32(0)+le32(1))
fixture=json.loads(Path(__file__).with_name('filter.json').read_text())
tweak=bytes.fromhex(fixture['tweak']);script=bytes.fromhex(fixture['script_pubkey'])
deposit=transaction([bytes([7])*32+le32(0)],[(1_000_000,script)]*2,0xffffffff)
deposit_id=D(deposit)
old=big(1_000_000)+deposit_id+le32(0)+tweak
change_tweak=H(old);change_witness=witness(change_tweak);change_script=b'\0\x20'+H(change_witness)
inputs=[deposit_id+le32(0),deposit_id+le32(1)];outputs=[(1_999_684,change_script)]
consolidation=transaction(inputs,outputs);consolidation_id=D(consolidation)
consolidation_sighash=sighash(inputs,outputs,0,bytes.fromhex(fixture['witness_script']),1_000_000)
withdraw_tweak=H(big(1_999_684)+consolidation_id+le32(0)+change_tweak)
withdraw_script=b'\0\x20'+H(witness(withdraw_tweak))
inputs=[consolidation_id+le32(0)];outputs=[(1_899_456,withdraw_script),(100_000,b'\0\x14'+bytes([8])*20)]
withdrawal=transaction(inputs,outputs)
result={"provenance":__doc__,"deposit_hex":deposit.hex(),"consolidation_hex":consolidation.hex(),"consolidation_txid_internal":consolidation_id.hex(),"consolidation_sighash0":consolidation_sighash.hex(),"withdrawal_hex":withdrawal.hex(),"withdrawal_txid_internal":D(withdrawal).hex(),"withdrawal_sighash0":sighash(inputs,outputs,0,change_witness,1_999_684).hex()}
Path(__file__).with_name('transactions.json').write_text(json.dumps(result,indent=2)+'\n')
for field in ('consolidation','withdrawal'):
    Path(__file__).with_name(field+'.hex').write_text(result[field+'_hex']+'\n')
print(json.dumps({k:v for k,v in result.items() if 'sighash' in k or 'txid' in k},indent=2))
