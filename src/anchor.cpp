#include "anchor.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "lde.h"

namespace anchor {
namespace {

uint16_t ReadU16(const uint8_t* p) {
  uint16_t v;
  memcpy(&v, p, 2);
  return v;
}
uint32_t ReadU32(const uint8_t* p) {
  uint32_t v;
  memcpy(&v, p, 4);
  return v;
}
uint64_t ReadU64(const uint8_t* p) {
  uint64_t v;
  memcpy(&v, p, 8);
  return v;
}

// Instructions longer than this are refused, which also bounds the sweep when
// the decoder loses sync inside a literal pool embedded in .text.
constexpr size_t kMaxInstLen = 15;

}  // namespace

bool Image::InitFromMapped(const uint8_t* base) {
  if (base == nullptr) return false;
  const uint8_t* p = base;
  if (p[0] != 'M' || p[1] != 'Z') return false;
  const uint32_t e_lfanew = ReadU32(p + 0x3C);
  if (memcmp(p + e_lfanew, "PE\0\0", 4) != 0) return false;
  base_ = base;
  owned_.clear();
  return Parse();
}

bool Image::InitFromFile(const std::string& path) {
  FILE* f = fopen(path.c_str(), "rb");
  if (f == nullptr) return false;
  fseek(f, 0, SEEK_END);
  const long size = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (size <= 0) {
    fclose(f);
    return false;
  }
  std::vector<uint8_t> file(static_cast<size_t>(size));
  const size_t got = fread(file.data(), 1, file.size(), f);
  fclose(f);
  if (got != file.size()) return false;

  // Rebuild the file as a mapped image so that RVA arithmetic matches a live
  // module exactly. Every header field is bounds checked first: this runs on
  // files handed in by hand, not only on a module the loader has validated.
  if (file.size() < 0x40) return false;
  const size_t nt = ReadU32(file.data() + 0x3C);
  if (nt + 24 > file.size() || memcmp(file.data() + nt, "PE\0\0", 4) != 0) {
    return false;
  }
  const uint16_t nsec = ReadU16(file.data() + nt + 6);
  const uint16_t size_opt = ReadU16(file.data() + nt + 20);
  const size_t opt = nt + 24;
  const size_t sec = opt + size_opt;
  if (opt + 68 > file.size() || sec + static_cast<size_t>(nsec) * 40 > file.size()) {
    return false;
  }

  const uint32_t size_of_image = ReadU32(file.data() + opt + 56);
  const uint32_t size_of_headers = ReadU32(file.data() + opt + 60);
  if (size_of_image < 0x1000) return false;
  owned_.assign(size_of_image, 0);
  const size_t headers = size_of_headers < file.size() ? size_of_headers : file.size();
  if (headers > owned_.size()) return false;
  memcpy(owned_.data(), file.data(), headers);

  for (uint16_t i = 0; i < nsec; ++i) {
    const uint8_t* s = file.data() + sec + i * 40;
    const uint32_t vsize = ReadU32(s + 8);
    const uint32_t va = ReadU32(s + 12);
    const uint32_t rawsize = ReadU32(s + 16);
    const uint32_t raw = ReadU32(s + 20);
    const uint32_t copy = vsize < rawsize ? vsize : rawsize;
    if (raw + copy <= file.size() && va + copy <= owned_.size()) {
      memcpy(owned_.data() + va, file.data() + raw, copy);
    }
  }
  base_ = owned_.data();
  return Parse();
}

bool Image::Parse() {
  sections_.clear();
  functions_.clear();
  const uint8_t* p = base_;
  const uint32_t e_lfanew = ReadU32(p + 0x3C);
  const uint16_t nsec = ReadU16(p + e_lfanew + 6);
  const uint16_t size_opt = ReadU16(p + e_lfanew + 20);
  const size_t opt = e_lfanew + 24;
  const uint16_t magic = ReadU16(p + opt);
  image_base_ = (magic == 0x20B) ? ReadU64(p + opt + 24) : ReadU32(p + opt + 28);
  const size_t sec = opt + size_opt;
  for (uint16_t i = 0; i < nsec; ++i) {
    const uint8_t* s = p + sec + i * 40;
    Section out;
    memset(&out, 0, sizeof(out));
    memcpy(out.name, s, 8);
    out.vsize = ReadU32(s + 8);
    out.va = ReadU32(s + 12);
    out.rawsize = ReadU32(s + 16);
    out.raw = ReadU32(s + 20);
    sections_.push_back(out);
  }

  const Section* pdata = section(".pdata");
  if (pdata == nullptr) return false;
  const uint32_t count = pdata->vsize / 12;
  for (uint32_t i = 0; i < count; ++i) {
    const uint8_t* e = At(pdata->va + i * 12, 12);
    if (e == nullptr) break;
    const uint32_t begin = ReadU32(e);
    if (begin == 0) continue;
    functions_.push_back({begin, ReadU32(e + 4), ReadU32(e + 8)});
  }
  std::sort(functions_.begin(), functions_.end(),
            [](const std::array<uint32_t, 3>& a, const std::array<uint32_t, 3>& b) {
              return a[0] < b[0];
            });
  return !sections_.empty();
}

const Section* Image::section(const char* name) const {
  for (const Section& s : sections_) {
    if (strncmp(s.name, name, 8) == 0) return &s;
  }
  return nullptr;
}

const Section* Image::section_containing(uint32_t rva) const {
  for (const Section& s : sections_) {
    const uint32_t span = s.vsize > s.rawsize ? s.vsize : s.rawsize;
    if (rva >= s.va && rva < s.va + span) return &s;
  }
  return nullptr;
}

const uint8_t* Image::At(uint32_t rva, uint32_t size) const {
  if (base_ == nullptr) return nullptr;
  const Section* s = section_containing(rva);
  if (s == nullptr) return nullptr;
  // For a live module a section's virtual size governs what is mapped; for the
  // host-side flat image the whole image is resident. Accept up to whichever of
  // the two sizes is larger, since the live mapping rounds up to pages.
  const uint32_t span = s->vsize > s->rawsize ? s->vsize : s->rawsize;
  if (rva - s->va + size > span) return nullptr;
  return base_ + rva;
}

std::string Image::CString(uint32_t rva, uint32_t limit) const {
  std::string out;
  for (uint32_t i = 0; i < limit; ++i) {
    const uint8_t* p = At(rva + i, 1);
    if (p == nullptr || *p == 0) break;
    out.push_back(static_cast<char>(*p));
  }
  return out;
}

bool Image::FindBytes(const char* section_name, const char* needle,
                      uint32_t needle_len, uint32_t* rva_out) const {
  const Section* s = section(section_name);
  if (s == nullptr || needle_len == 0) return false;
  const uint32_t span = s->vsize < s->rawsize ? s->vsize : s->rawsize;
  const uint8_t* p = At(s->va, span);
  if (p == nullptr) return false;
  if (needle_len > span) return false;
  for (uint32_t i = 0; i + needle_len <= span; ++i) {
    if (memcmp(p + i, needle, needle_len) == 0) {
      *rva_out = s->va + i;
      return true;
    }
  }
  return false;
}

std::vector<Ref> FindCodeRefs(const Image& img, uint64_t target_va) {
  std::vector<Ref> out;
  const std::vector<std::array<uint32_t, 3>>& funcs = img.Functions();
  for (const std::array<uint32_t, 3>& f : funcs) {
    const uint32_t begin = f[0];
    const uint32_t end = f[1];
    if (end <= begin) continue;
    const uint32_t limit = (end - begin) > 0x10000u ? begin + 0x10000u : end;
    uint32_t cur = begin;
    while (cur < limit) {
      const uint8_t* p = img.At(cur, kMaxInstLen);
      if (p == nullptr) break;
      const size_t len = lde::DecodeLength(p);
      if (len == 0) {  // refused / desynced: resynchronise one byte at a time
        cur += 1;
        continue;
      }
      size_t disp_off = 0;
      size_t disp_size = 0;
      if (lde::HasRipRelative(p, &disp_off, &disp_size) && disp_size == 4) {
        int32_t disp;
        memcpy(&disp, p + disp_off, 4);
        const uint64_t ref = static_cast<uint64_t>(img.image_base()) + cur + len + disp;
        if (ref == target_va) {
          out.push_back({begin, end, cur});
        }
      }
      cur += static_cast<uint32_t>(len);
    }
  }
  return out;
}

bool ResolveAnchor(const Image& img, const char* needle, std::vector<Ref>* refs_out,
                   uint32_t* string_rva_out) {
  const uint32_t len = static_cast<uint32_t>(strlen(needle));
  uint32_t srva = 0;
  if (!img.FindBytes(".rdata", needle, len, &srva)) return false;
  if (string_rva_out != nullptr) *string_rva_out = srva;
  if (refs_out != nullptr) {
    *refs_out = FindCodeRefs(img, img.image_base() + srva);
  }
  return true;
}

}  // namespace anchor
