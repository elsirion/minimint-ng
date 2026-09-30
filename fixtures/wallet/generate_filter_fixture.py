"""Independent public fixture generator: Python hashlib + OpenSSL EC arithmetic.
Not a guardian/client implementation; all small integer private keys here are public.
Run in nix-shell. EC API: docs.openssl.org/3.0/man3/EC_POINT_add/.
"""
import ctypes as C
import ctypes.util
import hashlib
import json
crypto=C.CDLL(ctypes.util.find_library('crypto'))
P=C.c_void_p

def fn(name,args,ret):
    f=getattr(crypto,name);f.argtypes=args;f.restype=ret;return f
new_group=fn('EC_GROUP_new_by_curve_name',[C.c_int],P)
new_point=fn('EC_POINT_new',[P],P)
ctx_new=fn('BN_CTX_new',[],P)
bn_bytes=fn('BN_bin2bn',[C.c_void_p,C.c_int,P],P)
bn_free=fn('BN_free',[P],None)
mul=fn('EC_POINT_mul',[P,P,P,P,P,P],C.c_int)
add=fn('EC_POINT_add',[P,P,P,P,P],C.c_int)
encode=fn('EC_POINT_point2oct',[P,P,C.c_int,P,C.c_size_t,P],C.c_size_t)
group=new_group(714);ctx=ctx_new()
def point_mul(point,n):
    raw=n.to_bytes(32,'big');bn=bn_bytes(raw,32,None)
    try: assert mul(group,point,bn,None,None,ctx)==1
    finally: bn_free(bn)
def public(point):
    out=C.create_string_buffer(33);assert encode(group,point,2,out,33,ctx)==33;return out.raw
keys=[]
for i in range(1,5):
    point=new_point(group);point_mul(point,i);keys.append(point)
key_map=bytes([4])+b''.join(bytes([i])+public(p) for i,p in enumerate(keys))
filter_key=hashlib.sha256(key_map).digest()
claimant=new_point(group);tweak_point=new_point(group);result=new_point(group)
point_mul(claimant,1)
def search():
    for scalar in range(1,1_000_000):
        claimant_key=public(claimant);tweak=hashlib.sha256(claimant_key).digest()
        point_mul(tweak_point,int.from_bytes(tweak,'big'))
        tweaked=[]
        for key in keys:
            assert add(group,result,key,tweak_point,ctx)==1;tweaked.append(public(result))
        witness=b'\x53'+b''.join(b'\x21'+key for key in sorted(tweaked))+b'\x54\xae'
        script=b'\x00\x20'+hashlib.sha256(witness).digest()
        digest=hashlib.sha256(bytes([34])+script+filter_key).digest()
        if digest.startswith(b'\x00\x00'):
            print(json.dumps({'guardian_scalars':[1,2,3,4],'claimant_scalar':scalar,'claimant_key':claimant_key.hex(),'tweak':tweak.hex(),'witness_script':witness.hex(),'script_pubkey':script.hex(),'filter_digest':digest.hex()},indent=2));break
        assert add(group,claimant,claimant,keys[0],ctx)==1
    else: raise RuntimeError('search bound reached')

if __name__ == "__main__":
    search()
