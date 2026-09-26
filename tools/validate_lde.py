"""Validate lde.cpp against capstone on a real Stellaris binary.

Ground truth is capstone: for each sampled function entry both decoders size the
first few instructions, and we require identical instruction boundaries.
"""

import os
import struct
import subprocess
import sys

import capstone

sys.path.insert(0, r"D:\学习\diplo_hook\tools")
from pe import Image  # noqa: E402

EXE = sys.argv[1] if len(sys.argv) > 1 else r"D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe"
N_FUNCS = int(sys.argv[2]) if len(sys.argv) > 2 else 20000
TOOL = r"D:\学习\diplo_action_hook_src\tools\lde_test.exe"
LIST = r"D:\学习\diplo_action_hook_src\tools\_rvas.txt"

img = Image(EXE)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

entries = [f[0] for f in img.funcs]
step = max(1, len(entries) // N_FUNCS)
sample = entries[::step]
print("funcs=%d sampled=%d" % (len(entries), len(sample)))

with open(LIST, "w") as fh:
    for r in sample:
        fh.write("%x\n" % r)

out = subprocess.run([TOOL, EXE, LIST], capture_output=True, text=True, check=True).stdout

stats = {"ok": 0, "refused": 0, "mismatch": 0, "short": 0}
bad = []
for line in out.splitlines():
    parts = line.split()
    if len(parts) != 5:
        continue
    rva = int(parts[0], 16)
    mine = []
    for p in parts[1:]:
        if p == "x":
            mine.append(0)
        else:
            mine.append(int(p))
    if parts[1] == "x":
        stats["short"] += 1
        continue
    if mine[0] == 0:
        stats["refused"] += 1
        continue

    off = img.off(rva)
    blob = img.data[off:off + 32]
    truth = []
    total = 0
    for ins in md.disasm(blob, rva):
        truth.append(ins.size)
        total += ins.size
        if len(truth) >= 4:
            break

    # compare boundary sets up to the shorter of the two
    n = min(len(mine), len(truth))
    a, b = 0, 0
    same = True
    for i in range(n):
        a += mine[i]
        b += truth[i]
        if a != b:
            same = False
            break
    if not same:
        stats["mismatch"] += 1
        if len(bad) < 15:
            bad.append((rva, mine, truth, blob.hex(" ")))
    else:
        stats["ok"] += 1

print(stats)
if bad:
    print("\n--- mismatches (rva, mine, capstone, bytes) ---")
    for rva, mine, truth, hx in bad:
        print("0x%08x mine=%s capstone=%s\n   %s" % (rva, mine, truth, hx))
