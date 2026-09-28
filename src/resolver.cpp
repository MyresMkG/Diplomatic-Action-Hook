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

// True when the instruction is `mov reg32, [reg64 + disp8]` reading |offset|
// from the first argument register (rcx on Win64).
bool IsMovFromRcx(const Insn& in, uint32_t offset) {
  // 8B 4x disp8   (mov ecx/eax/.. , [rcx + disp8])
  return in.len == 3 && in.p[0] == 0x8B && (in.p[1] & 0xC0) == 0x40 &&
         (in.p[1] & 0x07) == 0x01 && in.p[2] == offset;
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

// True when the instruction reads `[reg + 0x5c]`, i.e. the entry count of the
// database that |reg| points at.
bool ReadsOffset5c(const Insn& in, int reg) {
  if (reg < 0) return false;
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
  if (i + 2 >= in.len || in.p[i] != 0x8B) return false;
  const uint8_t modrm = in.p[i + 1];
  if ((modrm & 0xC0) != 0x40) return false;  // needs a disp8
  const int base = ((rex & 0x01) ? 8 : 0) + (modrm & 7);
  return base == reg && in.p[i + 2] == 0x5c;
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

  // Verified on 4.5.0 and 4.5.1 (Windows) and identical in the Linux dump: the
  // type's early members -- name at +0x10, token at +0x50 (both already used by
  // this hook), prerequisites at +0x58, then this int -- keep their layout, while
  // everything from the MTTH member onwards is shifted by 0x48 on Windows.
  r->ai_acceptance_base_offset = 0x78;
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
  {
    const std::vector<uint32_t> views =
        IntersectAnchors(img, {"diplo_actions_window", "favors_container", "actions_list"});
    if (views.empty()) {
      r.failure = "diplomacy view function not found";
      *out = r;
      return;
    }
    for (uint32_t view : views) {
      const std::vector<Insn> body = Walk(img, view);
      for (size_t i = 0; i < body.size(); ++i) {
        const uint32_t callee = CallTarget(body[i]);
        if (callee == 0) continue;
        const size_t csize = FuncSize(img, callee);
        if (csize == 0 || csize > 0x400) continue;  // the helper is tiny
        const std::vector<Insn> inner = Walk(img, callee);
        for (size_t j = 0; j < inner.size(); ++j) {
          if (!IsMovFromRcx(inner[j], r.type_token_offset)) continue;
          // the factory call is the first call after loading the token
          for (size_t k = j + 1; k < inner.size() && k < j + 6; ++k) {
            const uint32_t factory = CallTarget(inner[k]);
            if (factory != 0) {
              r.diplo_view = view;
              r.create_diplo_action = callee;
              r.create_empty_action = factory;
              break;
            }
          }
          if (r.create_empty_action != 0) break;
        }
        if (r.create_empty_action != 0) break;
      }
      if (r.create_empty_action != 0) break;
    }
    if (r.create_empty_action == 0) {
      r.failure = "CreateEmptyAction not reached through the diplomacy view";
      *out = r;
      return;
    }
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

    // The constructor resolves the action type by inlining the database lookup:
    //   mov  r10, [rip+disp]   ; the database singleton pointer variable
    //   mov  r9d, [r10+0x5c]   ; its entry count
    // Finding that pair gives the database, which is what the catch-up pass
    // needs when the hook is injected after the data has already been loaded.
    const std::vector<Insn> ctor = Walk(img, r.base_ctor);
    for (size_t i = 0; i + 1 < ctor.size(); ++i) {
      const int reg = RipLoadDestReg(ctor[i]);
      if (reg < 0) continue;
      // The count is read a few instructions later (after several stores), so
      // scan a small window rather than only the next instruction.
      bool reads_count = false;
      for (size_t k = i + 1; k < ctor.size() && k <= i + 16; ++k) {
        if (ReadsOffset5c(ctor[k], reg)) {
          reads_count = true;
          break;
        }
      }
      if (!reads_count) continue;
      const uint32_t trva = RipTargetRva(ctor[i]);
      if (trva == 0) continue;
      const anchor::Section* s = img.section_containing(trva);
      if (s == nullptr || strncmp(s->name, ".text", 8) == 0) continue;
      r.db_instance_ptr = trva;
      break;
    }
    if (r.db_instance_ptr == 0) {
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
  if (lexer == nullptr || !SafeReadable(lexer, 0x88)) return false;
  const uint8_t* p = static_cast<const uint8_t*>(lexer);
  memcpy(static_count, p + 0x84, 4);
  memcpy(dynamic_count, p + 0x64, 4);
  // The static keyword table is large and fixed; the dynamic list is appended to
  // as scripts are parsed (47956 entries were already there when the first action
  // type was constructed on 4.5.1), so this bound only has to reject a garbage
  // read, not a busy lexer.
  if (*static_count < 1000 || *static_count > 200000) return false;
  if (*dynamic_count > 0x100000) return false;
  return true;
}

}  // namespace diplo
