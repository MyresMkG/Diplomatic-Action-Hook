"""Full-population validation of lde.cpp plus a hook-feasibility census.

For every .pdata function entry in the binary:
  * compare instruction boundaries against capstone for the first 4 instructions
  * check whether the prologue can host a 5-byte jump, i.e. whole instructions
    tile >= 5 bytes without hitting an instruction the decoder refuses
"""

import subprocess
import sys

import capstone

sys.path.insert(0, r"D:\学习\diplo_hook\tools")
from pe import Image  # noqa: E402

EXE = sys.argv[1] if len(sys.argv) > 1 else r"D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe"
TOOL = r"D:\学习\diplo_action_hook_src\tools\lde_test.exe"
LIST = r"D:\学习\diplo_action_hook_src\tools\_rvas_all.txt"

img = Image(EXE)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

entries = [f[0] for f in img.funcs]
with open(LIST, "w") as fh:
    for r in entries:
        fh.write("%x\n" % r)

out = subprocess.run([TOOL, EXE, LIST], capture_output=True, text=True, check=True).stdout

stats = {"ok": 0, "mismatch": 0, "hookable5": 0, "unhookable": 0, "refused_first": 0}
bad = []
for line in out.splitlines():
    p = line.split()
    if len(p) != 5:
        continue
    rva = int(p[0], 16)
    mine = [0 if x == "x" else int(x) for x in p[1:]]
    if mine[0] == 0:
        stats["refused_first"] += 1
        stats["unhookable"] += 1
        continue

    off = img.off(rva)
    blob = img.data[off:off + 40]

    # hook feasibility: tile whole instructions until >= 5 bytes
    total = idx = 0
    while total < 5 and idx < 4:
        if mine[idx] == 0:
            break
        total += mine[idx]
        idx += 1
    if total >= 5:
        stats["hookable5"] += 1
    else:
        stats["unhookable"] += 1

    truth, t = [], 0
    for ins in md.disasm(blob, rva):
        truth.append(ins.size)
        t += ins.size
        if len(truth) >= 4:
            break
    n = min(len(mine), len(truth))
    a = b = 0
    same = True
    for i in range(n):
        a += mine[i]
        b += truth[i]
        if a != b:
            same = False
            break
    if same:
        stats["ok"] += 1
    else:
        stats["mismatch"] += 1
        if len(bad) < 10:
            bad.append((rva, mine, truth, blob[:24].hex(" ")))

print("entries=%d" % len(entries))
print(stats)
for rva, mine, truth, hx in bad:
    print("0x%08x mine=%s capstone=%s\n   %s" % (rva, mine, truth, hx))
