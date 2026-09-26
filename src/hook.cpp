#include "hook.h"

#include <windows.h>

#include <cstring>

#include "lde.h"

namespace hook {
namespace {

// A 5-byte jmp rel32 must reach its destination from the patched entry.
constexpr intptr_t kRel32Range = 0x7FFF0000;

// Reserve one page close enough to |target| that a rel32 jump reaches it.
// VirtualAlloc with an explicit base is the only way to guarantee this.
void* AllocateNear(const void* target, size_t size) {
  SYSTEM_INFO si;
  GetSystemInfo(&si);
  const uintptr_t gran = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000;
  const uintptr_t want = reinterpret_cast<uintptr_t>(target);
  const uintptr_t low = want > 0x70000000u ? want - 0x70000000u : 0x10000u;
  for (uintptr_t base = want & ~(gran - 1); base > low; base -= gran) {
    void* p = VirtualAlloc(reinterpret_cast<void*>(base), size,
                           MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (p != nullptr) return p;
    if (base < gran * 2) break;
  }
  // Fall back to anywhere; the caller detects the failed reach afterwards.
  return VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT,
                      PAGE_EXECUTE_READWRITE);
}

bool FitsRel32(const void* from, const void* to) {
  const intptr_t d = reinterpret_cast<const uint8_t*>(to) -
                     reinterpret_cast<const uint8_t*>(from);
  return d >= -kRel32Range && d <= kRel32Range;
}

void WriteAbsoluteJump(uint8_t* p, const void* dest) {
  // jmp qword ptr [rip + 0] ; <imm64>
  p[0] = 0xFF;
  p[1] = 0x25;
  *reinterpret_cast<uint32_t*>(p + 2) = 0;
  *reinterpret_cast<uint64_t*>(p + 6) = reinterpret_cast<uint64_t>(dest);
}

}  // namespace

bool RelocateInsn(const uint8_t* src, size_t length, uint8_t* dst,
                  const char** reason) {
  memcpy(dst, src, length);

  size_t disp_off = 0;
  size_t disp_size = 0;
  if (lde::HasRipRelative(src, &disp_off, &disp_size)) {
    // Recompute the absolute target, then re-encode it for the new location.
    int32_t old_disp;
    memcpy(&old_disp, src + disp_off, 4);
    const uint8_t* old_target =
        src + length + old_disp;  // absolute in the original image
    uint8_t* new_end = dst + length;
    const intptr_t new_disp = old_target - new_end;
    if (new_disp < INT32_MIN || new_disp > INT32_MAX) {
      if (reason) *reason = "rip-relative target out of range";
      return false;
    }
    const int32_t nd = static_cast<int32_t>(new_disp);
    memcpy(dst + disp_off, &nd, 4);
    return true;
  }

  // Peel any legacy/REX prefixes to find the opcode.
  size_t i = 0;
  while (i < length && (src[i] == 0x66 || src[i] == 0x67 || src[i] == 0xF0 ||
                        src[i] == 0xF2 || src[i] == 0xF3 || src[i] == 0x2E ||
                        src[i] == 0x36 || src[i] == 0x3E || src[i] == 0x26 ||
                        src[i] == 0x64 || src[i] == 0x65)) {
    i += 1;
  }
  if (i < length && src[i] >= 0x40 && src[i] <= 0x4F) i += 1;
  if (i >= length) {
    if (reason) *reason = "no opcode found";
    return false;
  }
  const uint8_t op = src[i];

  // Relative near branches and calls carry a rel32 that must be re-based. The
  // two-byte map has the same shape at 0F 80..8F (jcc rel32), and missing it
  // would leave a stale displacement in the trampoline.
  size_t rel32_at = 0;
  if (op == 0xE8 || op == 0xE9) {
    rel32_at = i + 1;
  } else if (op == 0x0F) {
    if (i + 1 >= length) {
      if (reason) *reason = "truncated two-byte opcode";
      return false;
    }
    const uint8_t op2 = src[i + 1];
    if (op2 < 0x80 || op2 > 0x8F) return true;  // no relative operand
    rel32_at = i + 2;
  }
  if (rel32_at != 0) {
    if (rel32_at + 4 > length) {
      if (reason) *reason = "truncated rel32";
      return false;
    }
    int32_t old_rel;
    memcpy(&old_rel, src + rel32_at, 4);
    const uint8_t* old_target = src + length + old_rel;
    const intptr_t new_rel = old_target - (dst + length);
    if (new_rel < INT32_MIN || new_rel > INT32_MAX) {
      if (reason) *reason = "relative branch out of range";
      return false;
    }
    const int32_t nr = static_cast<int32_t>(new_rel);
    memcpy(dst + rel32_at, &nr, 4);
    return true;
  }

  // Short relative branches carry a rel8; refuse unless it still fits.
  if (op == 0xEB || (op >= 0x70 && op <= 0x7F) || (op >= 0xE0 && op <= 0xE3)) {
    const size_t off = i + 1;
    if (off + 1 > length) {
      if (reason) *reason = "truncated rel8";
      return false;
    }
    const int8_t old_rel = static_cast<int8_t>(src[off]);
    const uint8_t* old_target = src + length + old_rel;
    const intptr_t new_rel = old_target - (dst + length);
    if (new_rel < -128 || new_rel > 127) {
      if (reason) *reason = "short branch out of range";
      return false;
    }
    dst[off] = static_cast<uint8_t>(static_cast<int8_t>(new_rel));
    return true;
  }

  return true;  // position independent
}

bool InlineHook::Install(void* target, void* detour, const char** reason) {
  if (reason) *reason = "ok";
  if (target == nullptr || detour == nullptr) {
    if (reason) *reason = "null target/detour";
    return false;
  }
  target_ = target;
  detour_ = detour;

  const uint8_t* code = reinterpret_cast<const uint8_t*>(target);

  // Steal whole instructions until at least 5 bytes are covered.
  size_t total = 0;
  std::vector<size_t> lens;
  while (total < 5) {
    if (total > 32) {
      if (reason) *reason = "prologue too long to relocate";
      return false;
    }
    const size_t n = lde::DecodeLength(code + total);
    if (n == 0) {
      if (reason) *reason = "undecodable instruction in prologue";
      return false;
    }
    lens.push_back(n);
    total += n;
  }
  stolen_ = total;
  saved_.assign(code, code + total);

  block_size_ = 0x1000;
  block_ = AllocateNear(target, block_size_);
  if (block_ == nullptr) {
    if (reason) *reason = "VirtualAlloc failed";
    return false;
  }
  uint8_t* tramp = static_cast<uint8_t*>(block_);
  uint8_t* gateway = tramp + 0x100;

  if (!FitsRel32(target, gateway)) {
    if (reason) *reason = "gateway out of rel32 range";
    return false;
  }

  // ---- trampoline: relocated prologue followed by a jump back ----
  size_t at = 0;
  for (size_t n : lens) {
    if (!RelocateInsn(code + at, n, tramp + at, reason)) return false;
    at += n;
  }
  WriteAbsoluteJump(tramp + at, code + stolen_);
  trampoline_ = tramp;

  // ---- gateway: absolute jump to the detour ----
  WriteAbsoluteJump(gateway, detour);
  gateway_ = gateway;

  // ---- patch the entry with a rel32 jump to the gateway ----
  DWORD old_protect = 0;
  if (!VirtualProtect(const_cast<uint8_t*>(code), stolen_, PAGE_EXECUTE_READWRITE,
                      &old_protect)) {
    if (reason) *reason = "VirtualProtect failed";
    return false;
  }
  uint8_t* p = const_cast<uint8_t*>(code);
  const intptr_t rel = gateway - (p + 5);
  p[0] = 0xE9;
  const int32_t r32 = static_cast<int32_t>(rel);
  memcpy(p + 1, &r32, 4);
  for (size_t i = 5; i < stolen_; ++i) p[i] = 0x90;  // pad with NOP
  FlushInstructionCache(GetCurrentProcess(), p, stolen_);
  VirtualProtect(p, stolen_, old_protect, &old_protect);
  return true;
}

void InlineHook::Remove() {
  if (target_ == nullptr || saved_.empty()) return;
  uint8_t* p = static_cast<uint8_t*>(target_);
  DWORD old_protect = 0;
  if (VirtualProtect(p, saved_.size(), PAGE_EXECUTE_READWRITE, &old_protect)) {
    memcpy(p, saved_.data(), saved_.size());
    FlushInstructionCache(GetCurrentProcess(), p, saved_.size());
    VirtualProtect(p, saved_.size(), old_protect, &old_protect);
  }
  target_ = nullptr;
}

InlineHook::~InlineHook() { Remove(); }

}  // namespace hook
