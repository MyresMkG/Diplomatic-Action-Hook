// Diagnostic: print the decoded instruction stream of a function and the calls
// the resolver would see, so a walk desync is easy to spot.
//
// usage: walk_test.exe <image> <rva> [count]

#include <cstdio>
#include <cstdlib>

#include "../src/anchor.h"
#include "../src/lde.h"

int main(int argc, char** argv) {
  if (argc < 3) return 2;
  anchor::Image img;
  if (!img.InitFromFile(argv[1])) return 2;
  const uint32_t func = static_cast<uint32_t>(strtoul(argv[2], nullptr, 0));
  const int limit = argc > 3 ? atoi(argv[3]) : 60;

  uint32_t rva = 0, end = 0;
  for (const auto& f : img.Functions()) {
    if (f[0] == func) {
      rva = f[0];
      end = f[1];
      break;
    }
  }
  if (rva == 0) {
    printf("0x%x is not a function start\n", func);
    return 1;
  }
  printf("function 0x%x..0x%x size=0x%x\n", rva, end, end - rva);

  int n = 0;
  uint32_t cur = rva;
  while (cur < end && n < limit) {
    const uint8_t* p = img.At(cur, 15);
    if (p == nullptr) break;
    const size_t len = lde::DecodeLength(p);
    char bytes[3 * 16 + 1];
    int b = 0;
    const size_t show = len ? len : 1;
    for (size_t i = 0; i < show && i < 16; ++i) {
      b += snprintf(bytes + b, sizeof(bytes) - b, "%02x ", p[i]);
    }
    if (len == 0) {
      printf("  %08x  DECODE FAILED            %s\n", cur, bytes);
      cur += 1;
      n += 1;
      continue;
    }
    char note[64] = "";
    if (p[0] == 0xE8 && len == 5) {
      int32_t rel;
      memcpy(&rel, p + 1, 4);
      snprintf(note, sizeof(note), "  call -> 0x%x", cur + 5 + rel);
    }
    printf("  %08x  len=%-2zu  %-22s%s\n", cur, len, bytes, note);
    cur += static_cast<uint32_t>(len);
    n += 1;
  }
  return 0;
}
