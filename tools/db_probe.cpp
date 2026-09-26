// Diagnostic for the database-singleton derivation: prints every rip-relative
// load in the generic action constructor and whether a following instruction
// reads [reg+0x5c].
//
// usage: db_probe.exe <image> <base_ctor_rva>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "../src/anchor.h"
#include "../src/lde.h"

struct Insn { uint32_t rva; const uint8_t* p; size_t len; };

static bool HasRip(const uint8_t* p, size_t* off, size_t* size) {
  return lde::HasRipRelative(p, off, size);
}

static int DestReg(const uint8_t* p, size_t len) {
  size_t i = 0;
  uint8_t rex = 0;
  while (i < len && (p[i] == 0x66 || p[i] == 0x67 || p[i] == 0xF0 || p[i] == 0xF2 || p[i] == 0xF3)) i++;
  if (i < len && p[i] >= 0x40 && p[i] <= 0x4F) { rex = p[i]; i++; }
  if (i + 1 >= len || p[i] != 0x8B) return -1;
  const uint8_t modrm = p[i + 1];
  if ((modrm & 0xC7) != 0x05) return -1;
  return ((rex & 0x04) ? 8 : 0) + ((modrm >> 3) & 7);
}

static bool Reads5c(const uint8_t* p, size_t len, int reg) {
  if (reg < 0) return false;
  size_t i = 0;
  uint8_t rex = 0;
  while (i < len && (p[i] == 0x66 || p[i] == 0x67 || p[i] == 0xF0 || p[i] == 0xF2 || p[i] == 0xF3)) i++;
  if (i < len && p[i] >= 0x40 && p[i] <= 0x4F) { rex = p[i]; i++; }
  if (i + 2 >= len || p[i] != 0x8B) return false;
  const uint8_t modrm = p[i + 1];
  if ((modrm & 0xC0) != 0x40) return false;
  const int base = ((rex & 0x01) ? 8 : 0) + (modrm & 7);
  return base == reg && p[i + 2] == 0x5c;
}

int main(int argc, char** argv) {
  if (argc < 3) return 2;
  anchor::Image img;
  if (!img.InitFromFile(argv[1])) return 2;
  const uint32_t ctor = static_cast<uint32_t>(strtoul(argv[2], nullptr, 0));
  uint32_t end = 0;
  for (const auto& f : img.Functions()) {
    if (f[0] == ctor) { end = f[1]; break; }
  }
  if (end == 0) { printf("not a function start\n"); return 1; }

  std::vector<Insn> body;
  for (uint32_t cur = ctor; cur < end;) {
    const uint8_t* p = img.At(cur, 15);
    if (p == nullptr) break;
    const size_t n = lde::DecodeLength(p);
    if (n == 0) { cur++; continue; }
    body.push_back({cur, p, n});
    cur += static_cast<uint32_t>(n);
  }
  printf("constructor 0x%x..0x%x, %zu instructions\n", ctor, end, body.size());

  for (size_t i = 0; i < body.size(); ++i) {
    size_t off = 0, size = 0;
    if (!HasRip(body[i].p, &off, &size)) continue;
    int32_t disp;
    memcpy(&disp, body[i].p + off, 4);
    const uint32_t target = body[i].rva + static_cast<uint32_t>(body[i].len) + disp;
    const uint32_t trva = static_cast<uint32_t>(target - img.image_base());
    const int reg = DestReg(body[i].p, body[i].len);
    const anchor::Section* s = img.section_containing(trva);
    int found_at = -1;
    for (size_t k = i + 1; k < body.size() && k <= i + 16; ++k) {
      if (Reads5c(body[k].p, body[k].len, reg)) { found_at = static_cast<int>(k); break; }
    }
    char bytes[3 * 12 + 1];
    int b = 0;
    for (size_t j = 0; j < body[i].len && j < 12; ++j)
      b += snprintf(bytes + b, sizeof(bytes) - b, "%02x ", body[i].p[j]);
    printf("  i=%-3zu 0x%08x len=%-2zu dst=%-3d target=0x%08x (%s) reads5c@%d   %s\n",
           i, body[i].rva, body[i].len, reg, trva, s ? s->name : "?", found_at, bytes);
  }
  return 0;
}
