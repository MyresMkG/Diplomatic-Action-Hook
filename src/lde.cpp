#include "lde.h"

#include <climits>

namespace lde {
namespace {

constexpr size_t kNoModRm = static_cast<size_t>(-1);

// Bytes consumed by the ModRM byte plus any SIB byte and displacement. When a
// SIB is present the displacement is selected by the SIB base field, not by the
// ModRM r/m field -- getting that wrong mis-sizes every `[index*scale+disp32]`
// addressing form.
size_t ModRmBytes(const uint8_t* p) {
  const uint8_t modrm = *p;
  const uint8_t mod = static_cast<uint8_t>(modrm >> 6);
  const uint8_t rm = static_cast<uint8_t>(modrm & 7);
  if (mod == 3) return 1;

  if (rm == 4) {  // SIB follows
    const uint8_t sib = p[1];
    size_t size = 2;  // ModRM + SIB
    if (mod == 0) {
      if ((sib & 7) == 5) size += 4;  // no base register -> disp32
    } else if (mod == 1) {
      size += 1;
    } else {
      size += 4;
    }
    return size;
  }

  if (mod == 0) return rm == 5 ? 5u : 1u;  // r/m=101 -> rip-relative disp32
  if (mod == 1) return 2u;
  return 5u;
}

// One decoded instruction shape.
struct Decoded {
  size_t length = 0;         // 0 => undecodable / intentionally refused
  size_t modrm_offset = kNoModRm;
};

Decoded Decode(const uint8_t* c) {
  Decoded out;
  size_t n = 0;
  bool opsize16 = false;
  bool rexw = false;

  // Legacy prefixes (REX must be adjacent to the opcode and is peeled later).
  for (int guard = 0; guard < 15; ++guard) {
    const uint8_t b = c[n];
    if (b == 0x66) {
      opsize16 = true;
      n += 1;
    } else if (b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 || b == 0x2E ||
               b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) {
      n += 1;
    } else {
      break;
    }
    if (n > 14) return out;
  }

  uint8_t op = c[n];
  if (op >= 0x40 && op <= 0x4F) {
    rexw = (op & 0x08) != 0;
    n += 1;
    op = c[n];
    if (op >= 0x40 && op <= 0x4F) return out;  // two REX prefixes: malformed
  }

  // Immediate sizes. iz is 2 with a 66 prefix else 4; iv is 8 with REX.W.
  const size_t immz = opsize16 ? 2 : 4;

  if (op == 0x0F) {
    const uint8_t op2 = c[n + 1];
    const size_t base = n + 2;
    if (op2 == 0x0F) return out;                                  // 3DNow
    if (op2 == 0x38) return {base + ModRmBytes(c + base), base};  // no immediate
    if (op2 == 0x3A) return {base + ModRmBytes(c + base) + 1, base};

    // No operands.
    if (op2 == 0x04 || op2 == 0x05 || op2 == 0x06 || op2 == 0x07 ||
        (op2 >= 0x08 && op2 <= 0x0C) || (op2 >= 0x30 && op2 <= 0x37) ||
        op2 == 0x77 || op2 == 0xA0 || op2 == 0xA1 || op2 == 0xA2 ||
        op2 == 0xA8 || op2 == 0xA9 || op2 == 0xAA ||
        (op2 >= 0xC8 && op2 <= 0xCF)) {
      return {base, kNoModRm};
    }
    if (op2 >= 0x80 && op2 <= 0x8F) return {base + 4, kNoModRm};  // Jcc rel32

    // ModRM + imm8.
    if (op2 == 0x70 || op2 == 0x71 || op2 == 0x72 || op2 == 0x73 ||
        op2 == 0xA4 || op2 == 0xAC || op2 == 0xBA || op2 == 0xC2 ||
        (op2 >= 0xC4 && op2 <= 0xC6)) {
      return {base + ModRmBytes(c + base) + 1, base};
    }

    // Everything else that carries a ModRM and no immediate.
    if (op2 <= 0x03 || op2 == 0x0D || (op2 >= 0x10 && op2 <= 0x2F) ||
        (op2 >= 0x40 && op2 <= 0x6F) || op2 == 0x74 || op2 == 0x75 ||
        op2 == 0x76 || (op2 >= 0x78 && op2 <= 0x7F) ||
        (op2 >= 0x90 && op2 <= 0x9F) || op2 == 0xA3 || op2 == 0xA5 ||
        op2 == 0xAB || op2 == 0xAD || op2 == 0xAE || op2 == 0xAF ||
        (op2 >= 0xB0 && op2 <= 0xB9) || (op2 >= 0xBB && op2 <= 0xBF) ||
        op2 == 0xC0 || op2 == 0xC1 || op2 == 0xC3 || op2 == 0xC7 ||
        op2 >= 0xD0) {
      return {base + ModRmBytes(c + base), base};
    }
    return out;  // undecodable two-byte opcode
  }

  n += 1;  // consume opcode; |n| indexes the first operand byte

  // --- ModRM, no immediate ---
  switch (op) {
    case 0x00: case 0x01: case 0x02: case 0x03:
    case 0x08: case 0x09: case 0x0A: case 0x0B:
    case 0x10: case 0x11: case 0x12: case 0x13:
    case 0x18: case 0x19: case 0x1A: case 0x1B:
    case 0x20: case 0x21: case 0x22: case 0x23:
    case 0x28: case 0x29: case 0x2A: case 0x2B:
    case 0x30: case 0x31: case 0x32: case 0x33:
    case 0x38: case 0x39: case 0x3A: case 0x3B:
    case 0x63:
    case 0x84: case 0x85: case 0x86: case 0x87:
    case 0x88: case 0x89: case 0x8A: case 0x8B:
    case 0x8C: case 0x8D: case 0x8E: case 0x8F:
    case 0xD0: case 0xD1: case 0xD2: case 0xD3:
    case 0xD8: case 0xD9: case 0xDA: case 0xDB:
    case 0xDC: case 0xDD: case 0xDE: case 0xDF:
    case 0xFE: case 0xFF:
      return {n + ModRmBytes(c + n), n};

    // --- ModRM + imm8 ---
    case 0x6B: case 0x80: case 0x83: case 0xC0: case 0xC1: case 0xC6:
      return {n + ModRmBytes(c + n) + 1, n};

    // --- ModRM + immz ---
    case 0x69: case 0x81: case 0xC7:
      return {n + ModRmBytes(c + n) + immz, n};

    // Group 3: an immediate only exists for the /0 and /1 extensions.
    case 0xF6: {
      const uint8_t reg = static_cast<uint8_t>((c[n] >> 3) & 7);
      return {n + ModRmBytes(c + n) + ((reg <= 1) ? 1u : 0u), n};
    }
    case 0xF7: {
      const uint8_t reg = static_cast<uint8_t>((c[n] >> 3) & 7);
      return {n + ModRmBytes(c + n) + ((reg <= 1) ? immz : 0u), n};
    }

    // --- AL/eAX with immediate ---
    case 0x04: case 0x0C: case 0x14: case 0x1C:
    case 0x24: case 0x2C: case 0x34: case 0x3C:
    case 0xA8:
      return {n + 1, kNoModRm};
    case 0x05: case 0x0D: case 0x15: case 0x1D:
    case 0x25: case 0x2D: case 0x35: case 0x3D:
    case 0xA9:
      return {n + immz, kNoModRm};

    // --- single-byte encodings, no operands ---
    case 0x50: case 0x51: case 0x52: case 0x53:
    case 0x54: case 0x55: case 0x56: case 0x57:
    case 0x58: case 0x59: case 0x5A: case 0x5B:
    case 0x5C: case 0x5D: case 0x5E: case 0x5F:
    case 0x6C: case 0x6D: case 0x6E: case 0x6F:
    case 0x90: case 0x91: case 0x92: case 0x93:
    case 0x94: case 0x95: case 0x96: case 0x97:
    case 0x98: case 0x99:
    case 0x9B: case 0x9C: case 0x9D: case 0x9E: case 0x9F:
    case 0xA4: case 0xA5: case 0xA6: case 0xA7:
    case 0xAA: case 0xAB: case 0xAC: case 0xAD: case 0xAE: case 0xAF:
    case 0xC3: case 0xC9: case 0xCB: case 0xCC: case 0xCE: case 0xCF:
    case 0xD7:
    case 0xEC: case 0xED: case 0xEE: case 0xEF:
    case 0xF1: case 0xF4: case 0xF5:
    case 0xF8: case 0xF9: case 0xFA: case 0xFB:
    case 0xFC: case 0xFD:
      return {n, kNoModRm};

    case 0x68:  // push immz
      return {n + immz, kNoModRm};
    case 0x6A:  // push imm8
      return {n + 1, kNoModRm};

    case 0xB0: case 0xB1: case 0xB2: case 0xB3:
    case 0xB4: case 0xB5: case 0xB6: case 0xB7:
      return {n + 1, kNoModRm};
    case 0xB8: case 0xB9: case 0xBA: case 0xBB:
    case 0xBC: case 0xBD: case 0xBE: case 0xBF:
      return {n + (rexw ? 8 : immz), kNoModRm};

    // --- branches ---
    case 0x70: case 0x71: case 0x72: case 0x73:
    case 0x74: case 0x75: case 0x76: case 0x77:
    case 0x78: case 0x79: case 0x7A: case 0x7B:
    case 0x7C: case 0x7D: case 0x7E: case 0x7F:
    case 0xE0: case 0xE1: case 0xE2: case 0xE3:
    case 0xEB:
      return {n + 1, kNoModRm};
    case 0xE8: case 0xE9:
      return {n + 4, kNoModRm};  // rel32 is unconditional in 64-bit

    // --- misc immediate forms ---
    case 0xE4: case 0xE5: case 0xE6: case 0xE7:
    case 0xCD:
      return {n + 1, kNoModRm};
    case 0xC2: case 0xCA:
      return {n + 2, kNoModRm};
    case 0xC8:
      return {n + 3, kNoModRm};

    // --- moffs: 8-byte offset in 64-bit addressing ---
    case 0xA0: case 0xA1: case 0xA2: case 0xA3:
      return {n + 8, kNoModRm};

    // EVEX and VEX are refused rather than guessed.
    case 0x62: case 0xC4: case 0xC5:
      return out;

    default:
      return out;
  }
}

}  // namespace

size_t DecodeLength(const uint8_t* code) { return Decode(code).length; }

bool HasRipRelative(const uint8_t* code, size_t* disp_offset, size_t* disp_size) {
  const Decoded d = Decode(code);
  if (d.length == 0 || d.modrm_offset == kNoModRm) return false;
  const uint8_t modrm = code[d.modrm_offset];
  if ((modrm >> 6) != 0) return false;
  if ((modrm & 7) != 5) return false;
  *disp_offset = d.modrm_offset + 1;
  *disp_size = 4;
  return true;
}

}  // namespace lde
