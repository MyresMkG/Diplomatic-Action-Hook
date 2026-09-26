"""Resolve "string anchor -> function" offline, the same way the DLL will at runtime.

Method (no disassembler needed): a rip-relative reference encodes its target as
    target = next_insn_addr + disp32
so scanning every 4-byte window of .text for |disp32| and computing
    next_insn_addr = target - disp32
turns into a direct hit test: the bytes just before that address must be a
rip-relative instruction ending exactly there. This finds `lea`/`mov`/`cmp`
references without decoding the whole section.
"""

import struct
import sys

sys.path.insert(0, r"D:\学习\diplo_hook\tools")
from pe import Image  # noqa: E402

# Opcodes that can carry a rip-relative memory operand, and their immediate
# operand sizes (0 = none). Keyed by the byte following any REX prefix.
OPCODES = {
    0x8D: 0, 0x8B: 0, 0x89: 0, 0x03: 0, 0x3B: 0, 0x39: 0, 0x01: 0, 0x0B: 0,
    0x85: 0, 0x84: 0, 0x2B: 0, 0x29: 0, 0x21: 0, 0x23: 0, 0x31: 0, 0x33: 0,
    0x0F: -1,  # two-byte: ModRM only for the forms we care about
}


def find_rip_refs(img, target_va):
    """Return (ref_insn_rva, insn_len) for every rip-relative reference."""
    tva, tvs, traw, trs = img.sec[".text"]
    lo = img.base + tva
    hi = lo + min(tvs, trs)
    out = []
    data = img.data
    for off in range(traw, traw + min(tvs, trs) - 4):
        disp = struct.unpack_from("<i", data, off)[0]
        nxt = target_va - disp          # candidate address of the next instruction
        if nxt < lo or nxt >= hi:
            continue
        for length in (7, 6, 8):
            insn = nxt - length
            if insn < lo:
                continue
            foff = traw + (insn - lo)
            if foff < traw:
                continue
            p = data[foff:foff + length]
            if len(p) < length:
                continue
            # REX? then opcode, then ModRM with mod=00 rm=101
            if length in (7, 8) and 0x40 <= p[0] <= 0x4F:
                op = p[1]
                modrm = p[2]
            elif length == 6:
                op = p[0]
                modrm = p[1]
            else:
                continue
            if (modrm & 0xC7) != 0x05:
                continue
            if op not in OPCODES:
                continue
            out.append((insn - img.base, length, off))
    return out


def func_of(img, rva):
    f = img.find_func(rva)
    return f


def resolve(img, needle):
    so = img.data.find(needle)
    if so < 0:
        return None, []
    srva = img.rva_of_off(so)
    sva = img.base + srva
    refs = find_rip_refs(img, sva)
    funcs = {}
    for rva, length, disp_off in refs:
        f = func_of(img, rva)
        if f is None:
            continue
        funcs.setdefault(f[0], []).append((rva, length))
    return (srva, sva), funcs


def main():
    exe = sys.argv[1] if len(sys.argv) > 1 else r"D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe"
    img = Image(exe)
    print("image base 0x%x, pdata funcs %d" % (img.base, len(img.funcs)))
    anchors = sys.argv[2:] or [
        b"Diplomatic action is missing token: ",
        b"Creation of dynamic token",
        b"keywords may not start with a digit",
        b"common/diplomatic_actions",
        b"diplo_actions_window",
        b"favors_container",
    ]
    for a in anchors:
        s, funcs = resolve(img, a)
        if s is None:
            print("\n%-45s : STRING NOT FOUND" % a.decode())
            continue
        print("\n%-45s : string rva=0x%x va=0x%x" % (a.decode(), s[0], s[1]))
        if not funcs:
            print("    no code references")
        for fstart in sorted(funcs):
            f = img.find_func(fstart)
            refs = funcs[fstart]
            print("    func 0x%08x..0x%08x size=0x%-6x refs=%d  %s"
                  % (f[0], f[1], f[1] - f[0], len(refs),
                     " ".join("0x%x" % r[0] for r in refs[:6])))


if __name__ == "__main__":
    main()
