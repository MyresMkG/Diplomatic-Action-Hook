"""Locate everything the AI-propose hook needs, in any Stellaris 4.5.x exe.

usage: py ai_propose_probe.py [exe]

Steps (all derived from content, never from RVAs):
  1. ".should_ai_propose" string -> the function that references it
     (CDiplomaticAction::ScriptedShouldAIPropose).
  2. the giant per-token dispatch: the .pdata function with the most
     "mov edx,<token>; mov rcx,rax; call <ctor>" sites.
  3. every `lea rax,[rip+disp]` in that dispatch -> concrete action vtables.
  4. for each vtable slot offset, count how many vtables hold a function that
     calls ScriptedShouldAIPropose: the offset is the ShouldAIPropose slot.
  5. the base vtable: from the generic constructor the dispatch votes for.
"""

import collections
import struct
import sys

sys.path.insert(0, r"D:\学习\analysis")
from token_table import load_sections, off_to_va, va_to_off  # noqa: E402
from disasm_tool import parse_pdata, find_func  # noqa: E402

EXE = sys.argv[1] if len(sys.argv) > 1 else r"D:\学习\stellaris_4.5.exe"
data, image_base, sections = load_sections(EXE)
funcs = parse_pdata(data, sections)
TEXT = next(s for s in sections if s[0] == ".text")
tstart, tend = image_base + TEXT[1], image_base + TEXT[1] + TEXT[2]


def blob(rva, n):
    off = va_to_off(image_base + rva, image_base, sections)
    if off is None:
        return b""
    return data[off:off + n]


def q(rva):
    b = blob(rva, 8)
    return struct.unpack_from("<Q", b)[0] if len(b) == 8 else None


def sec_of(rva):
    for name, sva, vsize, raw, rawsize in sections:
        if sva <= rva < sva + vsize:
            return name
    return None


print("exe: %s" % EXE)

# ---- 1. ScriptedShouldAIPropose ------------------------------------------
needle = b".should_ai_propose"
soff = data.find(needle)
if soff < 0:
    print("FAIL: '.should_ai_propose' string not found")
    sys.exit(1)
sva = off_to_va(soff, image_base, sections)
print("string '.should_ai_propose' at RVA 0x%x" % (sva - image_base))
refs = []
blob_off = va_to_off(image_base + TEXT[1], image_base, sections)
tb = data[blob_off:blob_off + TEXT[4]]
for i in range(0, len(tb) - 4):
    disp = struct.unpack_from("<i", tb, i)[0]
    end_va = image_base + TEXT[1] + i + 4
    st = i + 4 - 7
    if st < 0 or tb[st] not in (0x48, 0x4C):
        continue
    if tb[st + 1] not in (0x8D, 0x8B) or (tb[st + 2] & 0xC7) != 0x05:
        continue
    if end_va + disp == sva:
        refs.append(TEXT[1] + st)
scripted = 0
for r in refs:
    f = find_func(funcs, r)
    print("  ref rva 0x%x -> func 0x%x (size 0x%x)" % (r, f[0], f[1] - f[0]))
    scripted = f[0]
if scripted == 0:
    print("FAIL: no reference to the string")
    sys.exit(1)
print("ScriptedShouldAIPropose = RVA 0x%x" % scripted)


def calls_target(func_rva, target, scan=0x400):
    f = find_func(funcs, func_rva)
    if f is None:
        return False
    body = blob(f[0], min(f[1] - f[0], scan))
    for j in range(len(body) - 5):
        if body[j] == 0xE8:
            rel = struct.unpack_from("<i", body, j + 1)[0]
            if f[0] + j + 5 + rel == target:
                return True
    return False


# ---- 2. the per-token dispatch ------------------------------------------
# Find every "BA <imm32> 48 8B C8 / 48 89 C1  E8 rel32" site and group by the
# enclosing .pdata function.
sites = collections.defaultdict(collections.Counter)
alloc = collections.defaultdict(collections.Counter)
sizes = collections.defaultdict(list)
for name, sva2, vsize, raw, rawsize in sections:
    if name != ".text":
        continue
    b = data[raw:raw + rawsize]
    base = sva2
    for i in range(0, len(b) - 14):
        if b[i] == 0xBA and b[i + 5:i + 8] in (b"\x48\x8b\xc8", b"\x48\x89\xc1") \
                and b[i + 8] == 0xE8:
            rel = struct.unpack_from("<i", b, i + 9)[0]
            at = base + i
            f = find_func(funcs, at)
            if f:
                sites[f[0]][at + 13 + rel] += 1
        if b[i] == 0xB9:
            size = struct.unpack_from("<I", b, i + 1)[0]
            if 0x30 <= size <= 0x400 and b[i + 5] == 0xE8:
                rel = struct.unpack_from("<i", b, i + 6)[0]
                at = base + i
                f = find_func(funcs, at)
                if f:
                    alloc[f[0]][at + 10 + rel] += 1
                    sizes[f[0]].append(size)

disp = max(sites, key=lambda k: sum(sites[k].values()))
votes = sites[disp]
print("dispatch func 0x%x .. 0x%x, %d ctor sites"
      % (disp, find_func(funcs, disp)[1], sum(votes.values())))
ctor = votes.most_common(1)[0][0]
print("generic ctor = RVA 0x%x (%d votes)" % (ctor, votes.most_common(1)[0][1]))
print("largest class size in dispatch: 0x%x" % max(sizes[disp]))

# ---- 3. concrete vtables -------------------------------------------------
vtables = set()
dblob = blob(disp, find_func(funcs, disp)[1] - disp)
for i in range(0, len(dblob) - 7):
    if dblob[i] == 0x48 and dblob[i + 1] == 0x8D and dblob[i + 2] == 0x05:
        d = struct.unpack_from("<i", dblob, i + 3)[0]
        tgt = disp + i + 7 + d
        if sec_of(tgt) == ".rdata":
            vtables.add(tgt)
print("concrete vtables in dispatch: %d" % len(vtables))

# ---- 4. the ShouldAIPropose slot ----------------------------------------
hist = collections.Counter()
hits = collections.defaultdict(list)
for v in sorted(vtables):
    for off in range(0, 0x100, 8):
        val = q(v + off)
        if val is None or not (tstart <= val < tend):
            continue
        if calls_target(val - image_base, scripted):
            hist[off] += 1
            hits[off].append(v)
print("ShouldAIPropose slot histogram:")
for off, n in hist.most_common(5):
    print("  +0x%03x : %d vtables" % (off, n))
slot = hist.most_common(1)[0][0] if hist else 0
print("==> ShouldAIPropose slot = +0x%x" % slot)

# ---- 5. base vtable ------------------------------------------------------
base_vtable = 0
cblob = blob(ctor, find_func(funcs, ctor)[1] - ctor)
for i in range(0, len(cblob) - 10):
    if cblob[i] == 0x48 and cblob[i + 1] == 0x8D and cblob[i + 2] == 0x05:
        if cblob[i + 7] == 0x48 and cblob[i + 8] == 0x89 and (cblob[i + 9] & 0xC7) == 0x01:
            d = struct.unpack_from("<i", cblob, i + 3)[0]
            base_vtable = ctor + i + 7 + d
            break
print("base vtable = RVA 0x%x" % base_vtable)
if base_vtable and slot:
    for off in (slot, 0x70, 0x78, 0x48, 0x50, 0x60):
        val = q(base_vtable + off)
        rva = val - image_base if val else 0
        f = find_func(funcs, rva) if rva else None
        print("  base vtable +0x%03x -> 0x%08x %s" % (
            off, rva, ("func 0x%x size 0x%x" % (f[0], f[1] - f[0])) if f else ""))
    # the base implementation should be the "return 0" stub
    body = blob(q(base_vtable + slot) - image_base, 16)
    print("  base ShouldAIPropose body:", body.hex(" "))

# ---- 6. AI acceptance chain ---------------------------------------------
# ".ai_acceptance" -> GetScriptedAcceptance, and its only caller is
# GetAIAcceptance. `AI_acceptance_base_value` sits at type+0x78 in this layout
# (same as the Linux dump; the type's members from the MTTH onwards are shifted
# by 0x48 on Windows, but this early field is not).
soff = data.find(b".ai_acceptance")
if soff < 0:
    print("string '.ai_acceptance': NOT FOUND")
else:
    sva2 = off_to_va(soff, image_base, sections)
    print("string '.ai_acceptance' at RVA 0x%x" % (sva2 - image_base))
    refs2 = []
    for k in range(0, len(tb) - 4):
        disp = struct.unpack_from("<i", tb, k)[0]
        end_va = image_base + TEXT[1] + k + 4
        st = k + 4 - 7
        if st < 0 or tb[st] not in (0x48, 0x4C):
            continue
        if tb[st + 1] not in (0x8D, 0x8B) or (tb[st + 2] & 0xC7) != 0x05:
            continue
        if end_va + disp == sva2:
            refs2.append(TEXT[1] + st)
    for r in refs2:
        f = find_func(funcs, r)
        print("  ref rva 0x%x -> func 0x%x (size 0x%x)" % (r, f[0], f[1] - f[0]))
    if refs2:
        scripted_acceptance = find_func(funcs, refs2[0])[0]
        callers = set()
        for k in range(0, len(tb) - 5):
            if tb[k] == 0xE8:
                rel = struct.unpack_from("<i", tb, k + 1)[0]
                at = TEXT[1] + k
                if at + 5 + rel == scripted_acceptance:
                    f = find_func(funcs, at)
                    callers.add(f[0] if f else at)
        print("  its callers:", ["0x%x" % c for c in sorted(callers)])
        print("  ==> GetScriptedAcceptance = 0x%x, GetAIAcceptance = %s" % (
            scripted_acceptance,
            ("0x%x" % list(callers)[0]) if len(callers) == 1 else "(not unique!)"))
print("AI_acceptance_base_value offset = +0x78 (verified on 4.5.0 and 4.5.1)")
