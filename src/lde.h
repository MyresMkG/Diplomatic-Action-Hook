// Minimal x86-64 instruction length decoder.
//
// Only instruction *lengths* are needed: to place a 5-byte jump at a function
// entry we must steal a whole number of instructions, and the trampoline has to
// know where each stolen instruction ends. The opcode table below covers the
// full one-byte opcode map plus the prefixes that realistically appear in
// function prologues; VEX/EVEX and the 0F 38/3A maps are handled as far as
// length is concerned (the game is built without AVX in the hot paths we hook,
// and LdeDecode reports failure rather than guessing when it meets something it
// cannot size).
#pragma once

#include <cstdint>
#include <cstddef>

namespace lde {

// Length of the instruction at |code|, or 0 if it cannot be determined.
// Never reads more than 15 bytes (the architectural maximum).
size_t DecodeLength(const uint8_t* code);

// True when the instruction at |code| encodes a rip-relative memory operand.
// |disp_offset|/|disp_size| describe where that displacement lives, so the
// caller can rewrite it while relocating the instruction.
bool HasRipRelative(const uint8_t* code, size_t* disp_offset, size_t* disp_size);

}  // namespace lde
