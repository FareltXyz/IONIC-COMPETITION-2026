import struct
import time
import z3

# 1. Load VM bytecode
with open('dist/main', 'rb') as f:
    data = f.read()

r10_data = [struct.unpack('<I', data[0x33060 + 4*i : 0x33060 + 4*(i+1)])[0] for i in range(11)]
bc = data[0x330b4 : 0x330b4 + 0x6bea * 8]

op_names = {
    0: 'LOAD_IN', 1: 'LOAD_CONST', 2: 'LOAD_MEM', 3: 'STORE_MEM',
    4: 'MOV', 5: 'XOR', 6: 'AND', 7: 'SHL', 8: 'SHR', 9: 'ASSERT_EQ', 10: 'HALT'
}

instrs = []
for i in range(len(bc) // 8):
    raw_op, dst, src1, src2, imm = struct.unpack('<BBBBI', bc[i*8:(i+1)*8])
    op = r10_data[raw_op]
    instrs.append((op, op_names[op], dst, src1, src2, imm))

print(f'Total instructions: {len(instrs)}')

# 2. Compute QR mask bits for positions
SIZE = 33
def ft14622uewf(grid, r, c, val):
    if 1 <= r <= SIZE and 1 <= c <= SIZE:
        grid[r-1][c-1] = val

def fm29luvu5c(grid, cy, cx):
    for dy in range(-4, 5):
        for dx in range(-4, 5):
            d = max(abs(dx), abs(dy))
            ft14622uewf(grid, cy + dy, cx + dx, d != 2 and d != 4)

def ftrdchgx9u(grid, cy, cx):
    for dy in range(-2, 3):
        for dx in range(-2, 3):
            ft14622uewf(grid, cy + dy, cx + dx, max(abs(dx), abs(dy)) != 1)

def fzvvc6qy57():
    data, rem = 0x0b, 0x0b
    for _ in range(10):
        rem = ((rem << 1) ^ (0x537 if ((rem >> 9) & 1) != 0 else 0)) & 0xffffffff
    return ((data << 10) | rem) ^ 0x5412

def f0dmnewmrhul():
    grid = [[None]*SIZE for _ in range(SIZE)]
    fm29luvu5c(grid, 4, 4)
    fm29luvu5c(grid, 4, SIZE - 3)
    fm29luvu5c(grid, SIZE - 3, 4)
    for i in range(9, SIZE - 7):
        ft14622uewf(grid, 7, i, (i % 2) == 1)
        ft14622uewf(grid, i, 7, (i % 2) == 1)
    ftrdchgx9u(grid, 27, 27)
    bits = fzvvc6qy57()
    for i in range(6):
        ft14622uewf(grid, i + 1, 9, ((bits >> i) & 1) != 0)
    ft14622uewf(grid, 8, 9, ((bits >> 6) & 1) != 0)
    ft14622uewf(grid, 9, 9, ((bits >> 7) & 1) != 0)
    ft14622uewf(grid, 9, 8, ((bits >> 8) & 1) != 0)
    for i in range(9, 15):
        ft14622uewf(grid, 9, 15 - i, ((bits >> i) & 1) != 0)
    for i in range(8):
        ft14622uewf(grid, 9, SIZE - i, ((bits >> i) & 1) != 0)
    for i in range(8, 15):
        ft14622uewf(grid, SIZE - 14 + i, 9, ((bits >> i) & 1) != 0)
    ft14622uewf(grid, SIZE - 7, 9, True)
    return grid

def fwm6lea():
    grid = f0dmnewmrhul()
    result = []
    up = True
    right = SIZE
    while right >= 2:
        if right == 7:
            right -= 1
        for step in range(1, SIZE + 1):
            r = (SIZE - step + 1) if up else step
            for c in (right, right - 1):
                if grid[r-1][c-1] is None:
                    result.append((r, c))
        up = not up
        right -= 2
    return result

pos = fwm6lea()
masks = [1 if ((p[0] - 1 + p[1] - 1) % 3 == 0) else 0 for p in pos]

# 3. Setup Z3 Solver
s = z3.Solver()

# 52 character variables (printable ASCII: 0x21 to 0x7e)
chars = [z3.BitVec(f'char_{i}', 8) for i in range(52)]
for c in chars:
    s.add(c >= 0x21, c <= 0x7e)

# 416 raw bits
flag_bits = []
for c in chars:
    for bit_pos in range(7, -1, -1):
        flag_bits.append(z3.Extract(bit_pos, bit_pos, c)) # 1-bit BitVec

# Map to 807 VM input modules (BitVec 32 for VM execution)
in_modules = [None] * 807
for k in range(60, 476):
    bit_1 = flag_bits[k - 60]
    mask_val = masks[k]
    # in_modules[k] is bit_1 ^ mask_val, zero-extended to 32 bits
    mod_1 = bit_1 ^ mask_val
    in_modules[k] = z3.ZeroExt(31, mod_1)

# 4. Symbolically execute VM
regs = [z3.BitVecVal(0, 32) for _ in range(16)]
mem = [z3.BitVecVal(0, 32) for _ in range(128)]
consts = [z3.BitVecVal(0, 32), z3.BitVecVal(1, 32)]

t0 = time.time()
print('Starting symbolic execution...')

for idx, (op, name, dst, src1, src2, imm) in enumerate(instrs):
    if op == 0: # LOAD_IN
        regs[dst] = in_modules[imm]
    elif op == 1: # LOAD_CONST
        regs[dst] = consts[imm]
    elif op == 2: # LOAD_MEM
        regs[dst] = mem[imm]
    elif op == 3: # STORE_MEM
        mem[imm] = regs[src1]
    elif op == 4: # MOV
        regs[dst] = regs[src1]
    elif op == 5: # XOR
        regs[dst] = regs[src1] ^ regs[src2]
    elif op == 6: # AND
        regs[dst] = regs[src1] & regs[src2]
    elif op == 7: # SHL
        regs[dst] = regs[src1] << imm
    elif op == 8: # SHR
        regs[dst] = z3.LShR(regs[src1], imm)
    elif op == 9: # ASSERT_EQ
        s.add(regs[src1] == regs[src2])
    elif op == 10: # HALT
        pass

print(f'Symbolic execution finished in {time.time() - t0:.2f}s.')
print('Solving with Z3...')

t1 = time.time()
res = s.check()
print(f'Z3 check result: {res} in {time.time() - t1:.2f}s')

if res == z3.sat:
    m = s.model()
    inner = ''.join(chr(m[c].as_long()) for c in chars)
    flag = f'IONIC{{{inner}}}'
    print('FLAG FOUND!')
    print('Flag:', flag)
    with open('flag.txt', 'w') as f_out:
        f_out.write(flag + '\n')
else:
    print('Unsat or Unknown!')
