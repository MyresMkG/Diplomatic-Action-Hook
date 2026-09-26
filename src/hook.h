// Minimal x64 inline detour engine.
//
// A hook replaces the first whole instructions of a function with a 5-byte
// relative jump. Because a 5-byte jump can only reach within +/-2 GB, the jump
// lands on a gateway stub allocated near the target which then performs an
// absolute jump to the detour; the same allocation holds a trampoline (the
// stolen instructions plus a jump back) so the detour can still call the
// original function.
//
// The prologue is only ever patched when whole instructions tile at least 5
// bytes and every stolen instruction can be relocated; otherwise Install()
// fails and the game keeps running untouched.
#pragma once

#include <cstdint>
#include <vector>

namespace hook {

class InlineHook {
 public:
  InlineHook() = default;
  ~InlineHook();

  InlineHook(const InlineHook&) = delete;
  InlineHook& operator=(const InlineHook&) = delete;

  // Returns false (leaving |target| untouched) when the prologue cannot be
  // safely relocated. |reason| receives a short explanation.
  bool Install(void* target, void* detour, const char** reason);

  // Callable stand-in for the original function; valid only after a successful
  // Install().
  void* trampoline() const { return trampoline_; }

  void Remove();

  void* target() const { return target_; }
  size_t stolen() const { return stolen_; }

 private:
  void* target_ = nullptr;
  void* detour_ = nullptr;
  void* trampoline_ = nullptr;
  void* gateway_ = nullptr;
  void* block_ = nullptr;
  size_t block_size_ = 0;
  size_t stolen_ = 0;
  std::vector<uint8_t> saved_;
};

// Relocates |length| bytes of the instruction at |src| so it executes
// identically at |dst|. Fails when the instruction cannot be moved.
bool RelocateInsn(const uint8_t* src, size_t length, uint8_t* dst,
                  const char** reason);

}  // namespace hook
