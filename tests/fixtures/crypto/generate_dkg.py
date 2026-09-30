"""Independent affine arithmetic for public 3-of-4 test fixtures.

Written solely from spec/02-cryptography.md numbered prose and generator bytes.
Uses Python integer arithmetic; does not import native cryptographic libraries,
implementation modules, or any spec verification scripts. Test coefficients
5,7,11 are deliberately public and unsuitable as operational guardian secrets.
Run with `python3 tests/fixtures/crypto/generate_dkg.py` and compare stdout with
`dkg-three-of-four.txt`. Fp2 tuples are (real, imaginary).
"""
p = int("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16)
g2 = bytes.fromhex("93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8")
ZERO = (0, 0)
ONE = (1, 0)
def add(a, b): return ((a[0]+b[0])%p, (a[1]+b[1])%p)
def neg(a): return ((-a[0])%p, (-a[1])%p)
def sub(a, b): return add(a, neg(b))
def mul(a, b): return ((a[0]*b[0]-a[1]*b[1])%p, (a[0]*b[1]+a[1]*b[0])%p)
def power(a, n):
    result = ONE
    while n:
        if n & 1: result = mul(result, a)
        a = mul(a, a)
        n >>= 1
    return result
def inv(a):
    norm = (a[0]*a[0]+a[1]*a[1])%p
    assert norm
    inverse = pow(norm, p-2, p)
    return (a[0]*inverse%p, -a[1]*inverse%p)
def sqrt(z):
    if z == ZERO: return ZERO
    a = power(z, (p-3)//4)
    alpha = mul(mul(a, a), z)
    b = mul(a, z)
    candidate = mul((0,1),b) if alpha == neg(ONE) else mul(power(add(ONE,alpha),(p-1)//2),b)
    assert mul(candidate,candidate) == z
    return candidate
def greater(a, b): return (a[1],a[0]) > (b[1],b[0])
def encode(point):
    if point is None: return (bytes([0xc0])+bytes(95)).hex()
    x,y = point
    raw = bytearray(x[1].to_bytes(48,"big")+x[0].to_bytes(48,"big"))
    raw[0] |= 0x80 | (0x20 if greater(y,neg(y)) else 0)
    return raw.hex()
def point_add(a, b):
    if a is None: return b
    if b is None: return a
    x1,y1 = a; x2,y2 = b
    if x1 == x2:
        if y1 == neg(y2): return None
        slope = mul(mul((3,0),mul(x1,x1)),inv(mul((2,0),y1)))
    else: slope = mul(sub(y2,y1),inv(sub(x2,x1)))
    x3 = sub(sub(mul(slope,slope),x1),x2)
    y3 = sub(mul(slope,sub(x1,x3)),y1)
    return x3,y3
def point_mul(point, n):
    result = None
    while n:
        if n & 1: result = point_add(result,point)
        point = point_add(point,point)
        n >>= 1
    return result
raw = bytearray(g2)
sign = bool(raw[0]&0x20)
raw[0] &= 0x1f
x = (int.from_bytes(raw[48:],"big"),int.from_bytes(raw[:48],"big"))
y = sqrt(add(mul(mul(x,x),x),(4,4)))
if greater(y,neg(y)) != sign: y=neg(y)
generator = (x,y)
assert encode(generator) == g2.hex()
print("# Public DKG f(x)=5+7*x+11*x^2, x=guardian_id+1. Columns: scalar G2_compressed.")
for scalar in [5,23,63,125,209]:
    print(scalar,encode(point_mul(generator,scalar)))

# Negative fixture used in tests/crypto.rs: x=(2,0), lexicographically small y
# is a valid G2 curve point but not in its order-r subgroup.
r = int("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",16)
x = (2,0)
y = sqrt(add(mul(mul(x,x),x),(4,4)))
if greater(y,neg(y)): y=neg(y)
assert encode((x,y)) == "80"+"00"*94+"02"
assert point_mul((x,y),r) is not None
