#include "resolver.h"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <map>
#include <set>
#include <vector>

#include "lde.h"
#include "log.h"

namespace diplo {
namespace {

struct Insn {
  uint32_t rva;
  const uint8_t* p;
  size_t len;
};

size_t FuncSize(const anchor::Image& img, uint32_t rva) {
  for (const std::array<uint32_t, 3>& f : img.Functions()) {
    if (f[0] == rva) return f[1] - f[0];
    if (f[0] > rva) break;
  }
  return 0;
}

// Linear decode of one function. Stops early once |limit| instructions have been
// produced; a refused instruction resynchronises one byte at a time.
std::vector<Insn> Walk(const anchor::Image& img, uint32_t func, size_t limit = 4096) {
  std::vector<Insn> out;
  const size_t size = FuncSize(img, func);
  if (size == 0) return out;
  const uint32_t end = func + static_cast<uint32_t>(size);
  uint32_t cur = func;
  while (cur < end && out.size() < limit) {
    const uint8_t* p = img.At(cur, 15);
    if (p == nullptr) break;
    const size_t n = lde::DecodeLength(p);
    if (n == 0) {
      cur += 1;
      continue;
    }
    out.push_back({cur, p, n});
    cur += static_cast<uint32_t>(n);
  }
  return out;
}

uint32_t CallTarget(const Insn& in) {
  if (in.p[0] != 0xE8 || in.len != 5) return 0;
  int32_t rel;
  memcpy(&rel, in.p + 1, 4);
  return in.rva + 5 + rel;
}

// `mov ecx, [reg + disp]`: a 32-bit load of a pointer's first-argument slot.
//
// This is how the per-token factory receives the token -- every build loads the
// `CDiplomaticActionType` token into ecx and calls the factory in the next
// instruction. The base register is deliberately not fixed: the same sequence
// appears as `mov ecx, [rcx+0x50]` inside the out-of-line helper the 4.5 view
// calls, and as `mov ecx, [rbx+0x40]` / `mov ecx, [r14+0x40]` where the compiler
// inlined that helper into the view on 4.2.4 and 3.14. Both the disp8 and the
// disp32 encodings occur, so the displacement is decoded rather than compared
// against a constant.
//
// Stack bases are rejected: `[rsp+..]`/`[rbp+..]` slots hold locals, never the
// action type, and accepting them would make the pattern match far too much.
bool IsMovEcxFromPtr(const Insn& in, uint32_t* offset) {
  size_t i = 0;
  uint8_t rex = 0;
  while (i < in.len && (in.p[i] == 0x66 || in.p[i] == 0x67 || in.p[i] == 0xF0 ||
                        in.p[i] == 0xF2 || in.p[i] == 0xF3 || in.p[i] == 0x2E ||
                        in.p[i] == 0x36 || in.p[i] == 0x3E || in.p[i] == 0x26 ||
                        in.p[i] == 0x64 || in.p[i] == 0x65)) {
    i += 1;
  }
  if (i < in.len && in.p[i] >= 0x40 && in.p[i] <= 0x4F) {
    rex = in.p[i];
    i += 1;
  }
  if (i + 1 >= in.len || in.p[i] != 0x8B) return false;
  const uint8_t modrm = in.p[i + 1];
  if ((modrm & 0xC0) == 0xC0) return false;        // register form, no memory
  if (((modrm >> 3) & 7) != 1) return false;       // destination must be ecx
  const uint8_t mod = static_cast<uint8_t>(modrm >> 6);
  const uint8_t rm = static_cast<uint8_t>(modrm & 7);
  if (rm == 4) return false;                       // SIB: base is not in ModRM
  if (mod == 0 && rm == 5) return false;           // rip-relative
  const int base = ((rex & 0x01) ? 8 : 0) + rm;
  if (base == 4 || base == 5) return false;        // rsp / rbp
  int32_t disp = 0;
  if (mod == 1) {
    if (i + 2 >= in.len) return false;
    disp = static_cast<int8_t>(in.p[i + 2]);
  } else if (mod == 2) {
    if (i + 5 >= in.len) return false;
    memcpy(&disp, in.p + i + 2, 4);
  }
  if (disp < 0) return false;
  *offset = static_cast<uint32_t>(disp);
  return true;
}

// `mov rcx, rax`. Both encodings are legal and the compiler picks either:
//   48 89 C1   mov r/m64, r64   (r/m = rcx, reg = rax)
//   48 8B C8   mov r64, r/m64   (reg = rcx, r/m = rax)
bool IsMovRcxFromRax(const Insn& in) {
  if (in.len != 3 || in.p[0] != 0x48) return false;
  if (in.p[1] == 0x89) return in.p[2] == 0xC1;
  if (in.p[1] == 0x8B) return in.p[2] == 0xC8;
  return false;
}

// Largest byte offset the constructor writes to its object, i.e. the minimum
// number of bytes an instance needs. Stores are recognised through rcx and
// through any register it was copied into: the compiler keeps a second copy of
// `this` for the fields it writes last (4.5.1 writes the bytes up to +0x50
// through r8, after `mov r8, rcx`), so watching rcx alone reports too little.
uint32_t ObjectSizeFromCtor(const anchor::Image& img, uint32_t ctor) {
  uint32_t need = 0;
  bool holds_this[16] = {false};
  holds_this[1] = true;  // rcx, the first argument

  for (const Insn& in : Walk(img, ctor)) {
    const uint8_t* p = in.p;
    size_t i = 0;
    uint8_t rex = 0;
    while (i < in.len && p[i] != 0x0F &&
           (p[i] == 0x66 || p[i] == 0x67 || p[i] == 0xF0 || p[i] == 0xF2 ||
            p[i] == 0xF3 || p[i] == 0x2E || p[i] == 0x36 || p[i] == 0x3E ||
            p[i] == 0x26 || p[i] == 0x64 || p[i] == 0x65)) {
      i += 1;
    }
    if (i < in.len && p[i] >= 0x40 && p[i] <= 0x4F) {
      rex = p[i];
      i += 1;
    }
    if (i >= in.len) continue;

    uint32_t width = 0;
    size_t modrm_at = 0;
    bool store = false;
    if (p[i] == 0x89) {  // mov r/m, r
      width = (rex & 0x08) ? 8 : 4;
      modrm_at = i + 1;
      store = true;
    } else if (p[i] == 0x88) {  // mov r/m8, r8
      width = 1;
      modrm_at = i + 1;
      store = true;
    } else if (p[i] == 0x0F && i + 1 < in.len && p[i + 1] == 0x11) {  // movups
      width = 16;
      modrm_at = i + 2;
      store = true;
    } else if (p[i] == 0x8B) {  // mov r, r/m: only its register form matters
      modrm_at = i + 1;
    } else {
      continue;
    }
    if (modrm_at >= in.len) continue;
    const uint8_t modrm = p[modrm_at];
    const uint8_t mod = static_cast<uint8_t>(modrm >> 6);
    const uint8_t rm = static_cast<uint8_t>(modrm & 7);
    if (rm == 4) continue;  // SIB: the base register is not in the ModRM byte
    const int reg = ((rex & 0x04) ? 8 : 0) + ((modrm >> 3) & 7);
    const int base = ((rex & 0x01) ? 8 : 0) + rm;

    if (mod == 3) {  // register form: the pointer travels with the value
      if (p[i] == 0x89) {
        if (holds_this[reg]) holds_this[base] = true;
      } else if (p[i] == 0x8B && holds_this[base]) {
        holds_this[reg] = true;
      }
      continue;
    }
    if (mod == 0 && rm == 5) continue;  // rip-relative, no base register
    if (!store || !holds_this[base]) continue;

    uint32_t disp = 0;
    if (mod == 0) {
      disp = 0;
    } else if (mod == 1) {
      if (modrm_at + 1 >= in.len) continue;
      disp = static_cast<uint32_t>(static_cast<int8_t>(p[modrm_at + 1]));
    } else if (mod == 2) {
      int32_t d;
      memcpy(&d, p + modrm_at + 1, 4);
      disp = static_cast<uint32_t>(d);
    } else {
      continue;  // register form, not a memory store
    }
    const uint32_t end = disp + width;
    if (end > need) need = end;
  }
  return need;
}

// RVA of the target of a rip-relative memory operand, or 0 when there is none.
// Rip-relative arithmetic is relative to the *absolute* next-instruction
// address, so computing it from an RVA yields the target's RVA directly -- no
// image base may be added or subtracted here.
uint32_t RipTargetRva(const Insn& in) {
  size_t disp_off = 0;
  size_t disp_size = 0;
  if (!lde::HasRipRelative(in.p, &disp_off, &disp_size) || disp_size != 4) return 0;
  int32_t disp;
  memcpy(&disp, in.p + disp_off, 4);
  return in.rva + static_cast<uint32_t>(in.len) + static_cast<uint32_t>(disp);
}

// Destination register of `mov r64, [rip+disp]`, or -1 for any other shape.
int RipLoadDestReg(const Insn& in) {
  size_t i = 0;
  uint8_t rex = 0;
  while (i < in.len && (in.p[i] == 0x66 || in.p[i] == 0x67 || in.p[i] == 0xF0 ||
                        in.p[i] == 0xF2 || in.p[i] == 0xF3)) {
    i += 1;
  }
  if (i < in.len && in.p[i] >= 0x40 && in.p[i] <= 0x4F) {
    rex = in.p[i];
    i += 1;
  }
  if (i + 1 >= in.len || in.p[i] != 0x8B) return -1;
  const uint8_t modrm = in.p[i + 1];
  if ((modrm & 0xC7) != 0x05) return -1;  // not [rip+disp32]
  return ((rex & 0x04) ? 8 : 0) + ((modrm >> 3) & 7);
}

// A memory operand: base register, optional scaled index, displacement. Index
// and base are 0..15 register numbers, or -1 when absent.
struct MemRef {
  int base = -1;
  int index = -1;
  int scale = 1;
  int32_t disp = 0;
};

bool IsLegacyPrefix(uint8_t b) {
  return b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 || b == 0x2E ||
         b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65;
}

// ModRM register fields, REX extended. |rex| is the prefix byte (0 when absent).
inline int ModrmReg(uint8_t modrm, uint8_t rex) {
  return ((rex & 0x04) ? 8 : 0) + ((modrm >> 3) & 7);
}
inline int ModrmRm(uint8_t modrm, uint8_t rex) {
  return ((rex & 0x01) ? 8 : 0) + (modrm & 7);
}

// Decodes the memory operand of one of the one-byte opcodes the engine's data
// structure walks use. |opcode| receives the opcode byte, |rex| the REX prefix,
// |w64| whether the operand is 64-bit, and |mem| the address. Returns false for
// anything else, including register-form operands.
bool DecodeMemOp(const Insn& in, uint8_t* opcode, uint8_t* rex, bool* w64, MemRef* mem) {
  size_t i = 0;
  uint8_t r = 0;
  while (i < in.len && IsLegacyPrefix(in.p[i])) i += 1;
  if (i < in.len && in.p[i] >= 0x40 && in.p[i] <= 0x4F) {
    r = in.p[i];
    i += 1;
  }
  if (i + 1 >= in.len) return false;
  const uint8_t op = in.p[i];
  switch (op) {
    case 0x8B:  // mov r, r/m
    case 0x89:  // mov r/m, r
    case 0x63:  // movsxd r, r/m32
    case 0x39:  // cmp r/m, r
    case 0x3B:  // cmp r, r/m
      break;
    default:
      return false;
  }
  const uint8_t modrm = in.p[i + 1];
  const uint8_t mod = static_cast<uint8_t>(modrm >> 6);
  const uint8_t rm = static_cast<uint8_t>(modrm & 7);
  if (mod == 3) return false;  // register operand

  MemRef m;
  size_t disp_at = i + 2;
  if (rm == 4) {  // SIB byte follows
    if (disp_at >= in.len) return false;
    const uint8_t sib = in.p[disp_at];
    disp_at += 1;
    const int sbase = ((r & 0x01) ? 8 : 0) + (sib & 7);
    const int sindex = ((r & 0x02) ? 8 : 0) + ((sib >> 3) & 7);
    m.scale = 1 << (sib >> 6);
    m.base = (sbase == 5 && mod == 0) ? -1 : sbase;   // no base when disp32 only
    if (sindex != 4 || (r & 0x02)) m.index = sindex;  // index 4 = "none" without REX.X
  } else if (mod == 0 && rm == 5) {
    return false;  // rip-relative
  } else {
    m.base = ((r & 0x01) ? 8 : 0) + rm;
  }

  if (mod == 1) {
    if (disp_at >= in.len) return false;
    m.disp = static_cast<int8_t>(in.p[disp_at]);
  } else if (mod == 2) {
    if (disp_at + 4 > in.len) return false;
    memcpy(&m.disp, in.p + disp_at, 4);
  }

  *opcode = op;
  *rex = r;
  *w64 = (r & 0x08) != 0;
  *mem = m;
  return true;
}

// Reads the action type out of a `cmp [reg+disp], r32`: the database scan
// compares each entry's token against the constructor's argument through this
// instruction, so finding it confirms both the token offset and that the array
// walked really holds action types.
bool FoundTokenCompare(const std::vector<Insn>& body, size_t from, uint32_t token_offset) {
  for (size_t k = from; k < body.size() && k <= from + 24; ++k) {
    uint8_t op = 0, rex = 0;
    bool w64 = false;
    MemRef m;
    if (!DecodeMemOp(body[k], &op, &rex, &w64, &m)) continue;
    if (op != 0x39 && op != 0x3B) continue;
    if (m.base < 0 || m.index >= 0) continue;
    if (static_cast<uint32_t>(m.disp) == token_offset) return true;
  }
  return false;
}

// True for `test r, r`, the "is this zero" guard the compiler emits right after
// loading the entry count. The REX prefix varies (`45 85 c9` on 4.5, `85 c9` on
// 3.14), so the register form is what is checked rather than the exact bytes.
bool IsRegisterTest(const Insn& in) {
  size_t i = 0;
  while (i < in.len && IsLegacyPrefix(in.p[i])) i += 1;
  if (i < in.len && in.p[i] >= 0x40 && in.p[i] <= 0x4F) i += 1;
  if (i + 1 >= in.len || in.p[i] != 0x85) return false;
  return (in.p[i + 1] & 0xC0) == 0xC0;  // mod=11: register operand
}

// The database the base constructor looks the action type up in:
//
//   mov  rX, [rip+var]      ; the singleton pointer variable
//   ...                     ; several stores into `this`
//   mov  rYd, [rX+COUNT]    ; entry count   (32-bit)
//   test rYd, rYd / jle     ; "empty database" guard
//   mov  rZ, [rX+ENTRIES]   ; entry array   (64-bit)
//   ...                     ; linear scan comparing each entry's token
//
// Both field offsets move between builds (+0x50/+0x5c on 4.5, +0x40/+0x4c on
// 4.2.4 and 3.14), so they are read off this code rather than assumed. The
// shape is specific enough that exactly one register can satisfy it; when more
// than one does, nothing is returned rather than a guess.
bool FindDbLayout(const anchor::Image& img, uint32_t ctor, uint32_t token_offset,
                  uint32_t* db_ptr_rva, uint32_t* entries_off, uint32_t* count_off) {
  const std::vector<Insn> body = Walk(img, ctor);
  int found = 0;
  for (size_t i = 0; i < body.size(); ++i) {
    const int db_reg = RipLoadDestReg(body[i]);
    if (db_reg < 0) continue;
    uint32_t count = 0, entries = 0;
    bool got_count = false, got_entries = false;
    size_t guard_at = 0, entries_at = 0;
    for (size_t k = i + 1; k < body.size() && k <= i + 24; ++k) {
      uint8_t op = 0, rex = 0;
      bool w64 = false;
      MemRef m;
      if (!DecodeMemOp(body[k], &op, &rex, &w64, &m)) continue;
      if (m.base != db_reg || m.index >= 0 || m.disp < 0) continue;
      if (op != 0x8B && op != 0x63) continue;  // a load
      // `movsxd r64, [..]` is REX.W but still loads a 32-bit field, and 3.14
      // uses it for the count where 4.5 uses a plain `mov`.
      const bool loads_32 = (op == 0x63) || !w64;
      if (loads_32 && !got_count) {
        // The count is followed by the "is the database empty" guard.
        got_count = true;
        count = static_cast<uint32_t>(m.disp);
        guard_at = k;
      } else if (!loads_32 && !got_entries && got_count) {
        got_entries = true;
        entries = static_cast<uint32_t>(m.disp);
        entries_at = k;
        break;
      }
    }
    if (!got_count || !got_entries) continue;

    // The guard: `test r,r` right after the count load.
    bool guarded = false;
    for (size_t k = guard_at + 1; k < body.size() && k <= guard_at + 3; ++k) {
      if (IsRegisterTest(body[k])) {
        guarded = true;
        break;
      }
    }
    if (!guarded) continue;
    if (!FoundTokenCompare(body, entries_at, token_offset)) continue;

    const uint32_t trva = RipTargetRva(body[i]);
    if (trva == 0) continue;
    const anchor::Section* s = img.section_containing(trva);
    if (s == nullptr || strncmp(s->name, ".text", 8) == 0) continue;

    *db_ptr_rva = trva;
    *entries_off = entries;
    *count_off = count;
    found += 1;
  }
  return found == 1;
}

// MSVC's _purecall: `sub rsp,28; call _get_purecall_handler; test rax,rax; je +6;
// call [rip+..]; call _invoke_watson; int3`. The pattern is distinctive enough
// to identify the stub without symbols.
uint32_t FindPurecall(const anchor::Image& img) {
  const anchor::Section* t = img.section(".text");
  if (t == nullptr) return 0;
  const uint32_t span = t->vsize < t->rawsize ? t->vsize : t->rawsize;
  const uint8_t* p = img.At(t->va, span);
  if (p == nullptr) return 0;
  for (uint32_t i = 0; i + 32 <= span; ++i) {
    if (p[i] != 0x48 || p[i + 1] != 0x83 || p[i + 2] != 0xEC || p[i + 3] != 0x28) continue;
    if (p[i + 4] != 0xE8) continue;
    if (p[i + 9] != 0x48 || p[i + 10] != 0x85 || p[i + 11] != 0xC0) continue;
    if (p[i + 12] != 0x74 || p[i + 13] != 0x06) continue;
    if (p[i + 14] != 0xFF || p[i + 15] != 0x15) continue;
    if (p[i + 20] != 0xE8) continue;
    return t->va + i;
  }
  return 0;
}

// Distinct .rdata targets of `lea rax, [rip+disp]` inside |func|: the concrete
// class vtables the action dispatch installs.
std::vector<uint32_t> FindConcreteVtables(const anchor::Image& img, uint32_t func) {
  std::set<uint32_t> out;
  for (const Insn& in : Walk(img, func, 20000)) {
    if (in.len != 7 || in.p[0] != 0x48 || in.p[1] != 0x8D || in.p[2] != 0x05) continue;
    const uint32_t trva = RipTargetRva(in);
    if (trva == 0) continue;
    const anchor::Section* s = img.section_containing(trva);
    if (s == nullptr || strncmp(s->name, ".rdata", 8) != 0) continue;
    out.insert(trva);
  }
  return std::vector<uint32_t>(out.begin(), out.end());
}

std::vector<uint32_t> RefFuncs(const std::vector<anchor::Ref>& refs) {
  std::set<uint32_t> s;
  for (const anchor::Ref& r : refs) s.insert(r.func_rva);
  return std::vector<uint32_t>(s.begin(), s.end());
}

// Functions referencing every one of |needles|; the union is used when no
// common function exists, so one renamed string does not defeat the search.
std::vector<uint32_t> IntersectAnchors(const anchor::Image& img,
                                       const std::vector<const char*>& needles) {
  std::vector<std::set<uint32_t>> sets;
  for (const char* n : needles) {
    std::vector<anchor::Ref> refs;
    if (!anchor::ResolveAnchor(img, n, &refs, nullptr)) continue;
    std::set<uint32_t> s;
    for (uint32_t f : RefFuncs(refs)) s.insert(f);
    if (!s.empty()) sets.push_back(s);
  }
  if (sets.empty()) return {};
  std::set<uint32_t> acc = sets[0];
  for (size_t i = 1; i < sets.size(); ++i) {
    std::set<uint32_t> next;
    std::set_intersection(acc.begin(), acc.end(), sets[i].begin(), sets[i].end(),
                          std::inserter(next, next.begin()));
    if (!next.empty()) {
      acc.swap(next);
    } else {
      for (uint32_t v : sets[i]) acc.insert(v);
    }
  }
  return std::vector<uint32_t>(acc.begin(), acc.end());
}

uint32_t PickSmallest(const anchor::Image& img, std::vector<uint32_t> funcs) {
  if (funcs.empty()) return 0;
  std::sort(funcs.begin(), funcs.end(),
            [&](uint32_t a, uint32_t b) { return FuncSize(img, a) < FuncSize(img, b); });
  return funcs[0];
}

// Start of the .pdata range that contains |rva|. The engine's factory is called
// through a mid-function entry point on some builds, and every function here
// that walks a function body is keyed on the recorded start.
uint32_t ContainingFuncStart(const anchor::Image& img, uint32_t rva) {
  for (const std::array<uint32_t, 3>& f : img.Functions()) {
    if (rva >= f[0] && rva < f[1]) return f[0];
    if (f[0] > rva) break;
  }
  return 0;
}

// True when the code at |rva| contains a direct call or jump to |target|. A
// vtable slot may point into the middle of a shared code block -- the compiler
// merges identical thunks -- so instructions are decoded directly here instead
// of through Walk, which insists on a .pdata function entry.
bool ReferencesCode(const anchor::Image& img, uint32_t rva, uint32_t target,
                    uint32_t limit = 0x200) {
  uint32_t cur = rva;
  const uint32_t end = rva + limit;
  while (cur < end) {
    const uint8_t* p = img.At(cur, 15);
    if (p == nullptr) return false;
    const size_t len = lde::DecodeLength(p);
    if (len == 0) {
      cur += 1;
      continue;
    }
    if (len == 5 && (p[0] == 0xE8 || p[0] == 0xE9)) {
      int32_t rel;
      memcpy(&rel, p + 1, 4);
      if (cur + 5 + static_cast<uint32_t>(rel) == target) return true;
    }
    cur += static_cast<uint32_t>(len);
  }
  return false;
}

// True when the function at |rva| is one of the compiler's bare "return 0"
// stubs, e.g. `xor al, al; ret`. The base implementation of the AI gate is one
// of those, and finding one at the derived slot's offset is what confirms that
// the offset really is the gate rather than code that merely mentions it.
bool LooksLikeReturnZeroStub(const anchor::Image& img, uint32_t rva) {
  uint32_t cur = rva;
  const uint32_t end = rva + 0x20;
  bool zeroes_accumulator = false;
  while (cur < end) {
    const uint8_t* p = img.At(cur, 15);
    if (p == nullptr) return false;
    const size_t len = lde::DecodeLength(p);
    if (len == 0) return false;
    if (p[0] == 0xC2 || p[0] == 0xC3) return zeroes_accumulator;
    if (p[0] == 0xE8 || p[0] == 0xE9 || p[0] == 0xEB || p[0] == 0xFF || p[0] == 0xCC) {
      return false;  // a call, a jump or int3: not a one-line answer
    }
    if ((p[0] == 0x30 || p[0] == 0x31 || p[0] == 0x32 || p[0] == 0x33) && len == 2 &&
        p[1] == 0xC0) {
      zeroes_accumulator = true;  // xor al/eax, al/eax
    }
    if (p[0] == 0xB0 && len == 2 && p[1] == 0x00) zeroes_accumulator = true;  // mov al,0
    if (p[0] == 0xB8 && len == 5) {
      int32_t value;
      memcpy(&value, p + 1, 4);
      if (value == 0) zeroes_accumulator = true;  // mov eax,0
    }
    cur += static_cast<uint32_t>(len);
  }
  return false;
}

// The AI asks every candidate action whether it wants to propose itself, through
// one vtable slot; the base class answers a flat 0 there, which is why a
// synthesized action is only ever player-initiated. Neither the slot offset nor
// the engine's scripted gate is documented, so both are derived from the stock
// classes the engine itself builds:
//
//   * ScriptedShouldAIPropose is the function that references the localisation
//     key fragment ".should_ai_propose";
//   * the gate's slot is the offset at which the concrete action vtables the
//     per-token factory installs agree on holding a function that calls it;
//   * the base vtable's slot at that offset is a bare "return 0" stub.
//
// Anything less than that agreement leaves |ai_propose_slot| at 0, and the hook
// then keeps the feature out rather than guessing.
void ResolveAIPropose(const anchor::Image& img, Resolved* r) {
  std::vector<anchor::Ref> refs;
  if (!anchor::ResolveAnchor(img, ".should_ai_propose", &refs, nullptr)) {
    r->ai_propose_failure = "anchor not found: '.should_ai_propose'";
    return;
  }
  r->scripted_ai_propose = PickSmallest(img, RefFuncs(refs));
  if (r->scripted_ai_propose == 0) {
    r->ai_propose_failure = "no code references '.should_ai_propose'";
    return;
  }

  std::vector<uint32_t> vtables = FindConcreteVtables(img, r->create_empty_action);
  if (vtables.size() < 8) {
    const uint32_t enclosing = ContainingFuncStart(img, r->create_empty_action);
    if (enclosing != 0 && enclosing != r->create_empty_action) {
      vtables = FindConcreteVtables(img, enclosing);
    }
  }
  if (vtables.size() < 8) {
    r->ai_propose_failure = "too few concrete action vtables to derive the AI gate";
    return;
  }

  std::map<uint32_t, uint32_t> votes;  // slot offset -> vtables that gate on the script
  for (uint32_t vtable : vtables) {
    for (uint32_t off = 0; off < 0x100; off += 8) {
      const uint8_t* slot = img.At(vtable + off, 8);
      if (slot == nullptr) break;
      uint64_t value = 0;
      memcpy(&value, slot, 8);
      if (value < img.image_base()) continue;
      const uint32_t fn = static_cast<uint32_t>(value - img.image_base());
      if (img.section_containing(fn) == nullptr) continue;
      if (ReferencesCode(img, fn, r->scripted_ai_propose)) votes[off] += 1;
    }
  }
  uint32_t best = 0;
  uint32_t best_votes = 0;
  uint32_t runner_up = 0;
  for (const auto& kv : votes) {
    if (kv.second > best_votes) {
      runner_up = best_votes;
      best_votes = kv.second;
      best = kv.first;
    } else if (kv.second > runner_up) {
      runner_up = kv.second;
    }
  }
  if (best_votes < 5 || best_votes < runner_up * 2) {
    r->ai_propose_failure = "the stock action vtables do not agree on the AI gate slot";
    return;
  }
  for (uint32_t i = 0; i < r->pure_slot_count; ++i) {
    if (r->pure_slots[i] == best) {
      r->ai_propose_failure = "the agreed slot is a pure virtual of the base class";
      return;
    }
  }

  const uint8_t* slot = img.At(r->base_vtable + best, 8);
  uint64_t value = 0;
  if (slot == nullptr) {
    r->ai_propose_failure = "the base vtable has no slot at the agreed offset";
    return;
  }
  memcpy(&value, slot, 8);
  if (value < img.image_base() ||
      !LooksLikeReturnZeroStub(img, static_cast<uint32_t>(value - img.image_base()))) {
    r->ai_propose_failure =
        "the base class does not answer the agreed slot with a 'return 0' stub";
    return;
  }

  r->ai_propose_slot = best;
  r->ai_propose_votes = best_votes;
  r->ai_propose_failure = "ok";
}

// Every .pdata function that contains a direct call to |target|. The scan looks
// at raw bytes rather than at decoded instruction boundaries; a byte pair inside
// a literal pool could in principle be taken for a call, so the caller only
// accepts a single, shape-checked candidate.
std::set<uint32_t> CallerFuncs(const anchor::Image& img, uint32_t target) {
  std::set<uint32_t> out;
  const anchor::Section* text = img.section(".text");
  if (text == nullptr) return out;
  const uint32_t span = text->vsize < text->rawsize ? text->vsize : text->rawsize;
  const uint8_t* p = img.At(text->va, span);
  if (p == nullptr) return out;
  const std::vector<std::array<uint32_t, 3>>& funcs = img.Functions();
  size_t cursor = 0;
  for (uint32_t i = 0; i + 5 <= span; ++i) {
    if (p[i] != 0xE8) continue;
    int32_t rel;
    memcpy(&rel, p + i + 1, 4);
    const uint32_t at = text->va + i;
    if (at + 5 + static_cast<uint32_t>(rel) != target) continue;
    // Call sites come in ascending address order, so the search only ever moves
    // forward through the .pdata list.
    while (cursor + 1 < funcs.size() && funcs[cursor][1] <= at) cursor += 1;
    if (funcs[cursor][0] <= at && at < funcs[cursor][1]) out.insert(funcs[cursor][0]);
  }
  return out;
}

// How many direct calls a function contains. The acceptance scorer is a long
// per-token table, so this is the cheapest way to tell it apart from a thunk.
uint32_t DirectCallCount(const anchor::Image& img, uint32_t func) {
  uint32_t count = 0;
  for (const Insn& in : Walk(img, func, 4000)) {
    if (CallTarget(in) != 0) count += 1;
  }
  return count;
}

// The action name is a string object inside the type. The DLL has to read its
// length and text, so it needs to know where the text lives inside that object --
// and that moved: at +0x10 on 4.5, at +0x00 on 4.2.4 and 3.14.
//
// AddDynamicToken is handed exactly that object as its first argument and tests
// its capacity at the top of the function, so its prologue states the layout:
//
//   mov  rYd, [base+0x18]      ; the string's capacity
//   cmp  rYd, 0x10             ; against the small-string threshold
//
// |base| is the string, and the answer is how |base| is derived from the argument
// register: `lea base, [arg+K]` gives K, a plain `mov base, arg` gives 0.
bool FindNameDataOffset(const anchor::Image& img, uint32_t fn, uint32_t* out) {
  const std::vector<Insn> body = Walk(img, fn, 64);

  // Registers that hold the string object passed in as the first argument: rcx,
  // plus whatever the prologue copies it into.
  bool is_arg[16] = {false};
  is_arg[1] = true;
  for (const Insn& in : body) {
    if (in.len != 3 || in.p[0] != 0x48 || in.p[1] != 0x8B) continue;
    if ((in.p[2] & 0xC0) != 0xC0) continue;  // needs the register form
    if (ModrmRm(in.p[2], 0x48) != 1) continue;
    is_arg[ModrmReg(in.p[2], 0x48)] = true;
  }

  for (size_t k = 0; k + 1 < body.size(); ++k) {
    const Insn& load = body[k];
    if (load.len != 4 || load.p[0] != 0x48 || load.p[1] != 0x8B) continue;
    const uint8_t modrm = load.p[2];
    if ((modrm >> 6) != 1 || (modrm & 7) == 4) continue;  // [reg+disp8], no SIB
    if (load.p[3] != 0x18) continue;
    const int dest = ModrmReg(modrm, load.p[0]);
    const int base = ModrmRm(modrm, load.p[0]);

    const Insn& cmp = body[k + 1];
    if (cmp.len != 4 || cmp.p[0] != 0x48 || cmp.p[1] != 0x83) continue;
    if ((cmp.p[2] & 0xC0) != 0xC0) continue;
    // `83 /7 ib` is `cmp r/m64, imm8`: the operand is the rm field, and 7 is the
    // opcode extension that happens to occupy the reg field.
    if (ModrmRm(cmp.p[2], 0x48) != dest) continue;
    if (cmp.p[3] != 0x10) continue;

    // How was the string base derived from the argument?
    for (size_t j = k; j-- > 0;) {
      const Insn& def = body[j];
      if (def.len < 3 || def.p[0] != 0x48) continue;
      if (def.p[1] == 0x8D && def.len == 4 && (def.p[2] >> 6) == 1 &&
          (def.p[2] & 7) != 4 && ModrmReg(def.p[2], 0x48) == base) {
        if (is_arg[ModrmRm(def.p[2], 0x48)] && def.p[3] > 0 && def.p[3] <= 0x20) {
          *out = def.p[3];
          return true;
        }
      }
      if (def.p[1] == 0x8B && def.len == 3 && (def.p[2] & 0xC0) == 0xC0 &&
          ModrmReg(def.p[2], 0x48) == base) {
        if (is_arg[ModrmRm(def.p[2], 0x48)]) {
          *out = 0;
          return true;
        }
      }
    }
  }
  return false;
}

// CStaticLexer keeps the static keyword count and the dynamic token count in two
// adjacent members, and AddDynamicToken -- already anchored on its log string --
// is where it reads them to work out the token being created. The two loads sit
// back to back off the singleton, so both offsets and their distance are read
// from the code. The absolute values move: +0x84/+0x64 on 4.5 and 4.2.4, but
// +0x7c/+0x5c on 3.14.
constexpr uint32_t kLexerCounterDelta = 0x20;

bool FindLexerCounters(const anchor::Image& img, uint32_t add_dynamic_token,
                       uint32_t* static_off, uint32_t* dynamic_off) {
  const std::vector<Insn> body = Walk(img, add_dynamic_token, 2048);
  int found = 0;
  for (size_t k = 0; k + 1 < body.size(); ++k) {
    uint8_t op1 = 0, rex1 = 0, op2 = 0, rex2 = 0;
    bool w1 = false, w2 = false;
    MemRef m1, m2;
    if (!DecodeMemOp(body[k], &op1, &rex1, &w1, &m1)) continue;
    if (!DecodeMemOp(body[k + 1], &op2, &rex2, &w2, &m2)) continue;
    if (op1 != 0x8B || op2 != 0x8B || w1 || w2) continue;  // two 32-bit loads
    if (m1.base < 0 || m2.index >= 0 || m1.index >= 0) continue;
    if (m1.base != m2.base) continue;
    if (m1.disp < 0 || m2.disp < 0) continue;
    const uint32_t a = static_cast<uint32_t>(m1.disp);
    const uint32_t b = static_cast<uint32_t>(m2.disp);
    if (a <= b || a - b != kLexerCounterDelta) continue;
    if (a < 0x40 || a > 0x200) continue;
    *static_off = a;
    *dynamic_off = b;
    found += 1;
  }
  return found == 1;
}

// Distance from the token to `AI_acceptance_base_value` inside the action type,
// measured on 4.5.0/4.5.1 (+0x50 -> +0x78) and on 4.2.4 (+0x40 -> +0x68).
constexpr uint32_t kAcceptanceBaseDelta = 0x28;

// `AI_acceptance_base_value` is a plain int in the action type, but the engine
// reads it only from inside the per-token acceptance table, which can never know
// a token this DLL invented. Resolving the scorer and the field lets the hook add
// the value back for those tokens.
//
// The chain is narrow: ".ai_acceptance" is referenced by exactly one function
// (GetScriptedAcceptance, the evaluator of the scripted `ai_acceptance` field)
// and that function has exactly one caller (GetAIAcceptance). The field offset is
// the one this build was verified against; game_hooks.cpp additionally checks the
// value distribution in the database before it trusts the read.
void ResolveAIAcceptance(const anchor::Image& img, Resolved* r) {
  r->ai_acceptance_failure = "anchor not found: '.ai_acceptance'";
  std::vector<anchor::Ref> refs;
  if (!anchor::ResolveAnchor(img, ".ai_acceptance", &refs, nullptr)) return;
  r->scripted_acceptance = PickSmallest(img, RefFuncs(refs));
  if (r->scripted_acceptance == 0) {
    r->ai_acceptance_failure = "no code references '.ai_acceptance'";
    return;
  }

  const std::set<uint32_t> callers = CallerFuncs(img, r->scripted_acceptance);
  if (callers.size() != 1) {
    r->ai_acceptance_failure = "the scripted acceptance does not have a single caller";
    return;
  }
  r->get_ai_acceptance = *callers.begin();
  const uint32_t size = FuncSize(img, r->get_ai_acceptance);
  if (size == 0 || size > 0x2000) {
    r->ai_acceptance_failure = "the acceptance scorer is not a normal-sized function";
    return;
  }
  if (DirectCallCount(img, r->get_ai_acceptance) < 8) {
    r->ai_acceptance_failure =
        "the acceptance scorer does not look like a per-token table";
    return;
  }

  // `AI_acceptance_base_value` sits a fixed distance after the token in the flat
  // run of simple members the type constructor writes directly, so the offset is
  // taken relative to the token rather than written down as an absolute: on 4.5
  // the token is at +0x50 and this int at +0x78, on 4.2.4 they are +0x40 and
  // +0x68. game_hooks.cpp still validates the value distribution in the live
  // database before it trusts the read, so a build whose members are packed
  // differently loses the setting rather than scoring actions wrongly.
  r->ai_acceptance_base_offset = r->type_token_offset + kAcceptanceBaseDelta;
  r->ai_acceptance_failure = "ok";
}

}  // namespace

void ResolveAll(const anchor::Image& img, Resolved* out) {
  Resolved r;

  // ---- step 1: the two directly anchored functions ------------------------
  {
    std::vector<anchor::Ref> refs;
    if (!anchor::ResolveAnchor(img, "Diplomatic action is missing token: ", &refs, nullptr)) {
      r.failure = "anchor not found: 'Diplomatic action is missing token: '";
      *out = r;
      return;
    }
    r.type_ctor = PickSmallest(img, RefFuncs(refs));
    if (r.type_ctor == 0) {
      r.failure = "no code references 'Diplomatic action is missing token: '";
      *out = r;
      return;
    }
  }
  {
    std::vector<anchor::Ref> refs;
    if (!anchor::ResolveAnchor(img, "Creation of dynamic token", &refs, nullptr)) {
      r.failure = "anchor not found: 'Creation of dynamic token'";
      *out = r;
      return;
    }
    r.add_dynamic_token = PickSmallest(img, RefFuncs(refs));
    if (r.add_dynamic_token == 0) {
      r.failure = "no code references 'Creation of dynamic token'";
      *out = r;
      return;
    }
    for (const Insn& in : Walk(img, r.add_dynamic_token, 40)) {
      const uint32_t t = CallTarget(in);
      if (t != 0) {
        r.lexer_accessor = t;
        break;
      }
    }
    // Not fatal: a build whose counters cannot be pinned leaves the defaults in
    // place, and ReadTokenCounts re-checks the values it reads at runtime.
    FindLexerCounters(img, r.add_dynamic_token, &r.lexer_static_offset,
                      &r.lexer_dynamic_offset);
    // Same rule: an unreadable layout keeps the default, and the name readers
    // then fall back to the value the shipped build uses.
    FindNameDataOffset(img, r.add_dynamic_token, &r.name_data_offset);
  }

  // Both anchors must reach the same lexer accessor; that mutual agreement is a
  // strong signal that the two functions really are what we think they are.
  if (r.lexer_accessor != 0) {
    bool agrees = false;
    for (const Insn& in : Walk(img, r.type_ctor, 512)) {
      if (CallTarget(in) == r.lexer_accessor) agrees = true;
    }
    if (!agrees) {
      r.failure = "the two anchors disagree about the lexer accessor";
      *out = r;
      return;
    }
  }

  // ---- step 2: diplomacy view -> action helper -> per-token factory -------
  //
  // The chain is: the diplomacy view asks NDiplomacyUtil::CreateDiplomaticAction
  // for an object, that helper reads the token out of the CDiplomaticActionType
  // and passes it to CreateEmptyAction, the per-token factory.
  //
  // Where the helper lives is a compiler decision, not an engine one. On 4.5 the
  // view calls it out-of-line; on 4.2.4 and 3.14 it was inlined into the view and
  // the factory is called from there directly. Both shapes end identically --
  // `mov ecx, [<type>+T]` with the call to the factory in the very next
  // instruction -- so the search keys on that pair instead of on a call chain,
  // and the token offset T falls out of it rather than being assumed. T really
  // does move: it is 0x50 on 4.5 and 0x40 on 4.2.4 and 3.14.
  //
  // The factory is told apart from the view's other calls by the concrete class
  // vtables it installs: it is the switch over every action token, so it names
  // dozens of them, where the view's other calls name none.
  {
    struct Candidate {
      uint32_t factory = 0;
      uint32_t token_offset = 0;
      uint32_t helper = 0;  // 0 when the helper was inlined into the view
      uint32_t view = 0;
      size_t vtables = 0;
    };
    std::vector<Candidate> candidates;

    const std::vector<uint32_t> views =
        IntersectAnchors(img, {"diplo_actions_window", "favors_container", "actions_list"});
    if (views.empty()) {
      r.failure = "diplomacy view function not found";
      *out = r;
      return;
    }

    for (uint32_t view : views) {
      const std::vector<Insn> body = Walk(img, view);
      const auto offer = [&](uint32_t factory, uint32_t offset, uint32_t helper) {
        if (FuncSize(img, factory) <= 0x400) return;
        for (const Candidate& c : candidates) {
          if (c.factory == factory) return;
        }
        candidates.push_back({factory, offset, helper, view, 0});
      };
      for (size_t i = 0; i < body.size(); ++i) {
        const uint32_t callee = CallTarget(body[i]);
        if (callee == 0) continue;
        const size_t csize = FuncSize(img, callee);
        if (csize == 0) continue;
        if (csize <= 0x400) {
          // The helper is a separate function: find the token load inside it and
          // the call it feeds, which is the factory.
          const std::vector<Insn> inner = Walk(img, callee);
          for (size_t j = 0; j + 1 < inner.size(); ++j) {
            uint32_t offset = 0;
            if (!IsMovEcxFromPtr(inner[j], &offset)) continue;
            const uint32_t factory = CallTarget(inner[j + 1]);
            if (factory == 0) continue;
            offer(factory, offset, callee);
          }
        } else if (i > 0) {
          // The helper was inlined, so the token load sits in the view itself,
          // right before the call to the factory.
          uint32_t offset = 0;
          if (IsMovEcxFromPtr(body[i - 1], &offset)) offer(callee, offset, 0);
        }
      }
    }

    if (candidates.empty()) {
      r.failure = "CreateEmptyAction not reached through the diplomacy view";
      *out = r;
      return;
    }
    for (Candidate& c : candidates) {
      c.vtables = FindConcreteVtables(img, c.factory).size();
    }
    Candidate best = candidates[0];
    for (const Candidate& c : candidates) {
      if (c.vtables > best.vtables) best = c;
    }
    if (best.vtables < 3) {
      r.failure = "the action factory candidate installs no concrete class vtables";
      *out = r;
      return;
    }
    r.diplo_view = best.view;
    r.create_diplo_action = best.helper;
    r.create_empty_action = best.factory;
    r.type_token_offset = best.token_offset;
  }

  // ---- step 3: allocation, generic constructor and its vtable -------------
  {
    const std::vector<Insn> body = Walk(img, r.create_empty_action);
    std::map<uint32_t, int> ctor_votes;
    std::map<uint32_t, int> alloc_votes;
    uint32_t max_object_size = 0;
    for (size_t i = 0; i + 2 < body.size(); ++i) {
      const Insn& a = body[i];
      // mov ecx, <object size> ; call <operator new>
      if (a.len == 5 && a.p[0] == 0xB9) {
        uint32_t size;
        memcpy(&size, a.p + 1, 4);
        // Only class-sized requests; the dispatch also allocates buffers.
        if (size >= 0x30 && size <= 0x400) {
          const uint32_t t = CallTarget(body[i + 1]);
          if (t != 0) {
            alloc_votes[t] += 1;
            if (size > max_object_size) max_object_size = size;
          }
        }
      }
      // mov edx, <token> ; mov rcx, rax ; call <CDiplomaticAction ctor>
      if (a.len == 5 && a.p[0] == 0xBA && IsMovRcxFromRax(body[i + 1])) {
        const uint32_t t = CallTarget(body[i + 2]);
        if (t != 0) ctor_votes[t] += 1;
      }
    }
    if (ctor_votes.empty()) {
      r.failure = "generic action constructor call not found";
      *out = r;
      return;
    }
    // A generic constructor is used by many tokens; a one-off would be a
    // specialised subclass constructor, which we must not reuse.
    int best_votes = -1;
    for (const auto& kv : ctor_votes) {
      if (kv.second > best_votes) {
        best_votes = kv.second;
        r.base_ctor = kv.first;
      }
    }
    if (best_votes < 3) {
      r.failure = "no constructor used by several token cases";
      *out = r;
      return;
    }
    {
      int best_alloc = -1;
      for (const auto& kv : alloc_votes) {
        if (kv.second > best_alloc) {
          best_alloc = kv.second;
          r.alloc = kv.first;
        }
      }
      if (r.alloc == 0) {
        r.failure = "operator new call site not found in the action dispatch";
        *out = r;
        return;
      }
      if (FuncSize(img, r.base_ctor) == 0) {
        r.failure = "the generic action constructor is not a known function";
        *out = r;
        return;
      }
      if (max_object_size < 0x50) {
        r.failure = "no plausible CDiplomaticAction size found in the dispatch";
        *out = r;
        return;
      }
      // Every derived action class is at least as large as CDiplomaticAction,
      // and the dispatch allocates one for every token it knows, so the largest
      // class-sized request seen there is a sane ceiling for the byte count read
      // off the constructor's own field writes.
      const uint32_t from_ctor = ObjectSizeFromCtor(img, r.base_ctor);
      uint32_t size = from_ctor < max_object_size ? from_ctor : max_object_size;
      if (size < 0x50) size = 0x50;
      r.action_size = size;
      r.action_size_upper_bound = max_object_size;
      r.action_size_from_ctor = from_ctor;
    }

    // lea rax, [rip+disp] ; mov [rcx], rax   -> the vtable it installs
    for (const Insn& in : Walk(img, r.base_ctor)) {
      if (in.len != 7 || in.p[0] != 0x48 || in.p[1] != 0x8D || in.p[2] != 0x05) continue;
      const uint8_t* tail = img.At(in.rva + 7, 3);
      if (tail == nullptr) continue;
      if (tail[0] != 0x48 || tail[1] != 0x89 || (tail[2] & 0xC7) != 0x01) continue;
      int32_t disp;
      memcpy(&disp, in.p + 3, 4);
      r.base_vtable = in.rva + 7 + disp;
      break;
    }
    if (r.base_vtable == 0) {
      r.failure = "generic action vtable not found in the constructor";
      *out = r;
      return;
    }

    // CDiplomaticAction is abstract. The compiler puts MSVC's _purecall stub in
    // the slots of the base vtable that a derived class must fill in; using the
    // base vtable as a final vtable therefore crashes with "Pure Virtual
    // Function Call" the moment the diplomacy view touches the object. Locate
    // the stub and record which slots hold it, so the hook can supply its own
    // implementations for exactly those slots and refuse to guess otherwise.
    r.purecall = FindPurecall(img);
    if (r.purecall != 0) {
      for (uint32_t off = 0; off < 0x100; off += 8) {
        const uint8_t* slot = img.At(r.base_vtable + off, 8);
        if (slot == nullptr) break;
        uint64_t value = 0;
        memcpy(&value, slot, 8);
        if (value == img.image_base() + r.purecall) {
          if (r.pure_slot_count < 4) {
            r.pure_slots[r.pure_slot_count] = off;
          }
          r.pure_slot_count += 1;
        }
      }
    }
    if (r.purecall == 0 || r.pure_slot_count == 0) {
      r.failure = "could not identify the pure virtual slots of CDiplomaticAction";
      *out = r;
      return;
    }

    // Take the engine's copy helper from a stock concrete class's clone virtual:
    //   mov ecx, <size> ; call operator_new ; ... ; call <copy>
    {
      const std::vector<uint32_t> all = FindConcreteVtables(img, r.create_empty_action);
      for (uint32_t vt : all) {
        const uint8_t* slot = img.At(vt + 0x78, 8);
        if (slot == nullptr) continue;
        uint64_t value = 0;
        memcpy(&value, slot, 8);
        if (value < img.image_base()) continue;
        const uint32_t clone = static_cast<uint32_t>(value - img.image_base());
        if (clone == r.purecall) continue;
        const std::vector<Insn> body2 = Walk(img, clone);
        bool saw_alloc = false;
        for (const Insn& in : body2) {
          const uint32_t t = CallTarget(in);
          if (t == 0) continue;
          if (!saw_alloc) {
            saw_alloc = true;  // operator_new
            continue;
          }
          r.copy_fn = t;  // the next call is the copy helper
          break;
        }
        if (r.copy_fn != 0) break;
      }
    }

    // The constructor resolves the action type by inlining the database lookup,
    // which is also what the catch-up pass needs to reproduce when the hook is
    // injected after the data has already been loaded.
    if (!FindDbLayout(img, r.base_ctor, r.type_token_offset, &r.db_instance_ptr,
                      &r.db_entries_offset, &r.db_count_offset)) {
      r.failure = "database singleton not found in the constructor";
      *out = r;
      return;
    }
  }

  // ---- step 4: the AI's propose gate (optional) ---------------------------
  // Not being able to find it costs the new actions their AI initiative, not
  // their existence, so this step reports rather than fails.
  ResolveAIPropose(img, &r);

  // ---- step 5: the AI's acceptance score (optional) -----------------------
  // Same rule: `AI_acceptance_base_value` staying inert for new actions is a
  // missing feature, not a broken hook.
  ResolveAIAcceptance(img, &r);

  r.ok = true;
  r.failure = "ok";
  *out = r;
}

namespace {

// Only read through pointers we have confirmed are mapped.
bool SafeReadable(const void* addr, size_t size) {
  MEMORY_BASIC_INFORMATION mbi;
  if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) return false;
  if (mbi.State != MEM_COMMIT) return false;
  if ((mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) return false;
  const uintptr_t start = reinterpret_cast<uintptr_t>(addr);
  const uintptr_t region_end = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
  return start + size <= region_end;
}

}  // namespace

bool ReadTokenCounts(const Resolved& r, uint32_t* static_count, uint32_t* dynamic_count) {
  if (!r.ok || r.lexer_accessor == 0) return false;
  using Accessor = void* (*)();
  const uintptr_t module = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));
  const Accessor accessor = reinterpret_cast<Accessor>(module + r.lexer_accessor);
  if (!SafeReadable(reinterpret_cast<const void*>(accessor), 16)) return false;
  void* lexer = accessor();
  const uint32_t counters_end = (r.lexer_static_offset > r.lexer_dynamic_offset
                                     ? r.lexer_static_offset
                                     : r.lexer_dynamic_offset) +
                                4;
  if (lexer == nullptr || !SafeReadable(lexer, counters_end)) return false;
  const uint8_t* p = static_cast<const uint8_t*>(lexer);
  memcpy(static_count, p + r.lexer_static_offset, 4);
  memcpy(dynamic_count, p + r.lexer_dynamic_offset, 4);
  // The static keyword table is large and fixed; the dynamic list is appended to
  // as scripts are parsed (47956 entries were already there when the first action
  // type was constructed on 4.5.1), so this bound only has to reject a garbage
  // read, not a busy lexer.
  if (*static_count < 1000 || *static_count > 200000) return false;
  if (*dynamic_count > 0x100000) return false;
  return true;
}

}  // namespace diplo
