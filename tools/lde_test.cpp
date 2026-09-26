// Offline validation harness for lde.cpp.
//
// usage: lde_test.exe <image> <rva_list_file>
//   rva_list_file: one hex RVA per line
// prints one line per RVA: "<rva> <len1> <len2> <len3> <len4>"
// where lenN is the length of the Nth instruction, or 0 if undecodable.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "../src/lde.h"

static std::vector<uint8_t> g_image;

static uint32_t ReadU32(size_t off) {
  uint32_t v;
  memcpy(&v, g_image.data() + off, 4);
  return v;
}

static void LoadFile(const char* path) {
  FILE* f = fopen(path, "rb");
  if (!f) {
    fprintf(stderr, "cannot open %s\n", path);
    exit(2);
  }
  fseek(f, 0, SEEK_END);
  const long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  g_image.resize(static_cast<size_t>(n));
  const size_t got = fread(g_image.data(), 1, g_image.size(), f);
  fclose(f);
  if (got != g_image.size()) exit(2);
}

// Mirrors pe.Image.off() for a sectioned PE image: translate an RVA to a file
// offset using the section table.
struct Section {
  char name[9];
  uint32_t va, vsize, raw, rawsize;
};
static std::vector<Section> g_sections;

static void ParseSections() {
  const size_t e_lfanew = ReadU32(0x3C);
  const size_t coff = e_lfanew + 4;
  uint16_t nsec;
  memcpy(&nsec, g_image.data() + coff + 2, 2);
  uint16_t size_opt;
  memcpy(&size_opt, g_image.data() + coff + 16, 2);
  const size_t sec = coff + 20 + size_opt;
  for (uint16_t i = 0; i < nsec; ++i) {
    Section s;
    memset(&s, 0, sizeof(s));
    memcpy(s.name, g_image.data() + sec + i * 40, 8);
    memcpy(&s.vsize, g_image.data() + sec + i * 40 + 8, 4);
    memcpy(&s.va, g_image.data() + sec + i * 40 + 12, 4);
    memcpy(&s.rawsize, g_image.data() + sec + i * 40 + 16, 4);
    memcpy(&s.raw, g_image.data() + sec + i * 40 + 20, 4);
    g_sections.push_back(s);
  }
}

static size_t RvaToOff(uint32_t rva) {
  for (const Section& s : g_sections) {
    const uint32_t span = s.vsize > s.rawsize ? s.vsize : s.rawsize;
    if (rva >= s.va && rva < s.va + span) return s.raw + (rva - s.va);
  }
  return static_cast<size_t>(-1);
}

int main(int argc, char** argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: %s <image> <rva_list>\n", argv[0]);
    return 1;
  }
  LoadFile(argv[1]);
  ParseSections();

  FILE* lf = fopen(argv[2], "r");
  if (!lf) {
    fprintf(stderr, "cannot open %s\n", argv[2]);
    return 2;
  }
  char line[128];
  while (fgets(line, sizeof(line), lf)) {
    char* end = nullptr;
    const unsigned long rva = strtoul(line, &end, 16);
    if (end == line) continue;
    const size_t off = RvaToOff(static_cast<uint32_t>(rva));
    if (off == static_cast<size_t>(-1) || off + 32 > g_image.size()) {
      printf("%lx x x x x\n", rva);
      continue;
    }
    const uint8_t* p = g_image.data() + off;
    size_t total = 0;
    size_t lens[4] = {0, 0, 0, 0};
    for (int i = 0; i < 4; ++i) {
      const size_t n = lde::DecodeLength(p + total);
      lens[i] = n;
      if (n == 0) break;
      total += n;
    }
    printf("%lx %zu %zu %zu %zu\n", rva, lens[0], lens[1], lens[2], lens[3]);
  }
  fclose(lf);
  return 0;
}
