// Anchor resolution: find the game function that references a known string.
//
// The Windows binaries ship without symbols, and addresses change between
// patches, so hook targets are located at runtime instead of being hardcoded:
// a unique string literal in .rdata is looked up, every rip-relative instruction
// that references it is found by a linear sweep of the .pdata function table,
// and the enclosing function is reported.
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace anchor {

struct Section {
  char name[9];
  uint32_t va;
  uint32_t vsize;
  uint32_t raw;
  uint32_t rawsize;
};

// A PE image laid out the way Windows maps it, so RVAs are plain offsets from
// |base|. Works identically for a live module and for a host-side test harness.
class Image {
 public:
  bool InitFromMapped(const uint8_t* base);
  bool InitFromFile(const std::string& path);

  const uint8_t* base() const { return base_; }
  uint64_t image_base() const { return image_base_; }
  const std::vector<Section>& sections() const { return sections_; }
  const Section* section(const char* name) const;
  const Section* section_containing(uint32_t rva) const;

  bool Readable(uint32_t rva, uint32_t size) const { return At(rva, size) != nullptr; }
  const uint8_t* At(uint32_t rva, uint32_t size = 1) const;
  // NUL-terminated ASCII string at |rva|, or empty when unreadable.
  std::string CString(uint32_t rva, uint32_t limit = 512) const;

  // Search a section (".rdata" by default) for an exact byte sequence.
  bool FindBytes(const char* section_name, const char* needle, uint32_t needle_len,
                 uint32_t* rva_out) const;

  // .pdata triples: (begin_rva, end_rva, unwind_rva).
  const std::vector<std::array<uint32_t, 3>>& Functions() const { return functions_; }

 private:
  bool Parse();

  std::vector<uint8_t> owned_;
  const uint8_t* base_ = nullptr;
  uint64_t image_base_ = 0;
  std::vector<Section> sections_;
  std::vector<std::array<uint32_t, 3>> functions_;
};

struct Ref {
  uint32_t func_rva = 0;
  uint32_t func_end = 0;
  uint32_t ref_rva = 0;
};

// Every rip-relative reference to |target_va| inside an executable function.
std::vector<Ref> FindCodeRefs(const Image& img, uint64_t target_va);

// Convenience: locate |needle| in .rdata and return the referencing functions.
// |string_rva_out| receives the string's RVA when found.
bool ResolveAnchor(const Image& img, const char* needle,
                   std::vector<Ref>* refs_out, uint32_t* string_rva_out);

}  // namespace anchor
