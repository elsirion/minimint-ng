"""Independent CompactSize-versus-BigSize filter fixture; public test key map."""
import hashlib,json
from pathlib import Path
from generate_filter_fixture import filter_key
for nonce in range(1_000_000):
    script=bytes(249)+nonce.to_bytes(4,'little')
    digest=hashlib.sha256(bytes.fromhex('fdfd00')+script+filter_key).digest()
    if digest.startswith(bytes(2)):
        wrong=hashlib.sha256(bytes.fromhex('fd00fd')+script+filter_key).hexdigest()
        result={'script_length':253,'nonce':nonce,'script_hex':script.hex(),
                'compactsize_digest':digest.hex(),'incorrect_bigsize_digest':wrong}
        Path(__file__).with_name('long-script-filter.json').write_text(json.dumps(result,indent=2)+'\n')
        break
else:
    raise RuntimeError('fixture search bound reached')
