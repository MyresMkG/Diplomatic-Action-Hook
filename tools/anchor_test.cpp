// Host-side test harness for the runtime anchor resolver.
//
// usage: anchor_test.exe <image> <anchor> [<anchor> ...]
// Prints, per anchor: the string RVA and every function that references it,
// with the reference site and the function's first bytes (a usable signature).

#include <cstdio>
#include <string>
#include <vector>

#include "../src/anchor.h"

static void Dump(const anchor::Image& img, const char* needle) {
  printf("\n=== %s\n", needle);
  std::vector<anchor::Ref> refs;
  uint32_t srva = 0;
  if (!anchor::ResolveAnchor(img, needle, &refs, &srva)) {
    printf("    STRING NOT FOUND in .rdata\n");
    return;
  }
  printf("    string rva=0x%08x va=0x%llx\n", srva,
         (unsigned long long)(img.image_base() + srva));
  if (refs.empty()) {
    printf("    no code references\n");
    return;
  }
  for (const anchor::Ref& r : refs) {
    const uint8_t* p = img.At(r.func_rva, 24);
    char sig[3 * 24 + 4];
    int n = 0;
    for (int i = 0; i < 16 && p != nullptr; ++i) {
      n += snprintf(sig + n, sizeof(sig) - n, "%02x ", p[i]);
    }
    sig[n > 0 ? n - 1 : 0] = 0;
    printf("    func 0x%08x..0x%08x size=0x%-6x ref@0x%08x\n        bytes: %s\n",
           r.func_rva, r.func_end, r.func_end - r.func_rva, r.ref_rva, sig);
  }
}

int main(int argc, char** argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: %s <image> <anchor> [anchor...]\n", argv[0]);
    return 1;
  }
  anchor::Image img;
  if (!img.InitFromFile(argv[1])) {
    fprintf(stderr, "cannot load %s\n", argv[1]);
    return 2;
  }
  printf("image %s  base=0x%llx  sections=%zu  functions=%zu\n", argv[1],
         (unsigned long long)img.image_base(), img.sections().size(),
         img.Functions().size());
  for (int i = 2; i < argc; ++i) Dump(img, argv[i]);
  return 0;
}
