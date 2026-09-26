#include "game_hooks.h"

#include <windows.h>

#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <vector>
#include <string>

#include "anchor.h"
#include "hook.h"
#include "log.h"
#include "resolver.h"

namespace diplo {
namespace {

// ---- game function types (Microsoft x64 convention) ----
using TypeCtorFn = void(__fastcall*)(void* self, int index, const void* name);
using CreateEmptyActionFn = void*(__fastcall*)(int token);
using AddDynamicTokenFn = int(__fastcall*)(const void* name, bool always);
using LexerAccessorFn = void*(__fastcall*)();
using AllocFn = void*(__fastcall*)(size_t size);
using BaseCtorFn = void*(__fastcall*)(void* self, int token);
using CopyFn = void(__fastcall*)(void* dst, void* src);

Resolved g_resolved;
uintptr_t g_module = 0;

AddDynamicTokenFn g_add_dynamic_token = nullptr;
AllocFn g_alloc = nullptr;
BaseCtorFn g_base_ctor = nullptr;
CopyFn g_copy_fn = nullptr;

// Defined below; needed by the factory detour.
extern uintptr_t g_our_vtable[];
constexpr uint32_t kMaxVtableSlots = 64;

CreateEmptyActionFn g_orig_create_empty_action = nullptr;
TypeCtorFn g_orig_type_ctor = nullptr;

hook::InlineHook g_hook_type_ctor;
hook::InlineHook g_hook_create_empty_action;

std::mutex g_mutex;
// The engine's lexer is not documented as thread safe: hook 1 registers names on
// whichever thread loads the action data, while the catch-up pass registers them
// from its own thread. Every call into the engine is serialised on this lock,
// which is always taken *after* g_mutex so the order stays one-way.
std::mutex g_lexer_mutex;
bool g_counts_known = false;
uint32_t g_static_token_count = 0;
// Tokens created by this hook; only these are eligible for synthesis in the
// factory, so stock behaviour can never be changed.
std::set<int> g_our_tokens;
// Tokens whose construction has already been reported, so a view that asks for
// the same action repeatedly does not log (and flush) on every call.
std::set<int> g_reported_tokens;
// Diagnostics only.
std::set<std::string> g_seen_names;

// MSVC std::string layout: 16-byte SSO buffer or heap pointer, then size and
// capacity. This is only used to write readable log lines -- the same CString
// pointer is handed straight back to the engine, so nothing depends on it.
bool Readable(const void* p, size_t size);

bool SafeReadableText(const char* p) {  MEMORY_BASIC_INFORMATION mbi;
  if (p == nullptr || VirtualQuery(p, &mbi, sizeof(mbi)) == 0) return false;
  if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) return false;
  const uintptr_t start = reinterpret_cast<uintptr_t>(p);
  const uintptr_t region_end = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
  return start + 1 <= region_end;
}

const char* CStringText(const void* cstring) {
  if (cstring == nullptr) return "";
  const uint8_t* base = static_cast<const uint8_t*>(cstring) + 0x10;
  if (!Readable(base, 0x20)) return "<unreadable>";
  uint64_t capacity = 0;
  memcpy(&capacity, base + 0x18, 8);
  const char* text = reinterpret_cast<const char*>(base);
  if (capacity >= 16) {
    memcpy(&text, base, 8);
    if (text == nullptr) return "";
  }
  if (!SafeReadableText(text)) return "<bad pointer>";
  return text;
}

// Length of the string inside a CString, read from the inner std::string's size
// field. Used to skip the engine's empty placeholder names, which must not be
// registered as keywords.
bool CStringLength(const void* cstring, uint64_t* length) {
  if (cstring == nullptr) return false;
  const uint8_t* base = static_cast<const uint8_t*>(cstring) + 0x10;
  if (!Readable(base, 0x20)) return false;
  memcpy(length, base + 0x10, 8);
  return *length < 0x10000;
}

// Detour 1: give every scripted action name a real keyword token.
void __fastcall HookTypeCtor(void* self, int index, const void* name) {
  // The engine builds placeholder types with an empty name (the null object);
  // registering those would create a junk keyword and change how an unknown
  // name resolves, so they are left alone.
  uint64_t name_length = 0;
  const bool have_name = name != nullptr && CStringLength(name, &name_length);
  if (g_add_dynamic_token != nullptr && have_name && name_length != 0) {
    std::lock_guard<std::mutex> lock(g_mutex);
    int token = 0;
    {
      // Serialised with the catch-up pass: see g_lexer_mutex.
      std::lock_guard<std::mutex> lexer_lock(g_lexer_mutex);
      token = g_add_dynamic_token(name, true);
    }
    const char* text = CStringText(name);
    if (!g_counts_known) {
      uint32_t dyn = 0;
      if (ReadTokenCounts(g_resolved, &g_static_token_count, &dyn)) {
        g_counts_known = true;
        Log("token space: %u static keywords, %u dynamic already present",
            g_static_token_count, dyn);
      } else {
        Log("WARNING: could not read the lexer token counters; new tokens will "
            "not be recognised by the action factory");
      }
    }
    if (token > 0 && g_counts_known &&
        static_cast<uint32_t>(token) > g_static_token_count) {
      if (g_our_tokens.insert(token).second) {
        Log("registered keyword '%s' -> token %d (0x%x)", text, token, token);
      }
    } else if (g_seen_names.insert(text).second) {
      Log("existing keyword '%s' -> token %d", text, token);
    }
  }
  if (g_orig_type_ctor != nullptr) g_orig_type_ctor(self, index, name);
}

// Detour 2: hand the diplomacy view an action object for the new tokens.
void* __fastcall HookCreateEmptyAction(int token) {  void* object = nullptr;
  if (g_orig_create_empty_action != nullptr) object = g_orig_create_empty_action(token);
  if (object != nullptr) return object;

  bool ours = false;
  {
    std::lock_guard<std::mutex> lock(g_mutex);
    ours = g_our_tokens.count(token) != 0;
  }
  if (!ours || g_alloc == nullptr || g_base_ctor == nullptr || g_resolved.action_size == 0) {
    return nullptr;
  }

  void* memory = g_alloc(g_resolved.action_size);
  if (memory == nullptr) {
    Log("token %d: allocation for a generic action failed", token);
    return nullptr;
  }
  void* created = g_base_ctor(memory, token);  // initialises every field
  // Replace the abstract base vtable the constructor installed with our
  // concrete one; this is the step the engine's own factory performs for its
  // derived classes, and skipping it is what caused a pure-virtual crash.
  *static_cast<void**>(created) = g_our_vtable;

  // The constructor resolves the type through the database; confirm it landed on
  // the entry we registered rather than the null object.
  void* type = nullptr;
  memcpy(&type, static_cast<uint8_t*>(created) + g_resolved.action_type_offset, 8);
  int type_token = -1;
  MEMORY_BASIC_INFORMATION mbi;
  if (type != nullptr && VirtualQuery(type, &mbi, sizeof(mbi)) != 0 &&
      mbi.State == MEM_COMMIT) {
    memcpy(&type_token, static_cast<uint8_t*>(type) + g_resolved.type_token_offset, 4);
  }
  bool first = false;
  {
    // The diplomacy view asks for the same action every time it builds its list,
    // and this runs on the game's own thread, so it is logged once per token.
    std::lock_guard<std::mutex> lock(g_mutex);
    first = g_reported_tokens.insert(token).second;
  }
  if (first) {
    if (type_token == token) {
      Log("token %d: built a generic scripted diplomatic action", token);
    } else {
      Log("WARNING: token %d: built an action whose type token is %d; the game may "
          "ignore it", token, type_token);
    }
  }
  return created;
}

// ---- the synthesized class -------------------------------------------------
//
// CDiplomaticAction is abstract: two of its vtable slots are MSVC's _purecall
// stub, and the engine only ever installs *derived* vtables (the factory does
// `operator_new; base ctor; obj->vtable = derived`). Handing the base vtable to
// the diplomacy view therefore dies with "Pure Virtual Function Call".
//
// So the hook builds its own concrete vtable: the base vtable's slots, with the
// two pure slots filled in here.

uintptr_t g_our_vtable[kMaxVtableSlots] = {0};
std::map<void*, std::string> g_loc_names;  // type pointer -> localisation prefix

// Slot +0x70 returns the localisation-key prefix for the action. Every stock
// class hardcodes its own (ACTION_EMBASSY, improve_relations, ...), so a new
// action gets its type name instead -- which is exactly what the engine's own
// CDiplomaticActionType::PostReadInit checks its localisation keys against.
const char* __fastcall OurGetLocName(void* self) {
  if (self == nullptr) return "";
  void* type = nullptr;
  memcpy(&type, static_cast<uint8_t*>(self) + g_resolved.action_type_offset, 8);
  if (type == nullptr) return "";
  std::lock_guard<std::mutex> lock(g_mutex);
  auto it = g_loc_names.find(type);
  if (it != g_loc_names.end()) return it->second.c_str();
  std::string name = CStringText(static_cast<uint8_t*>(type) + 0x10);
  for (char& c : name) {
    if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
  }
  // std::map nodes are stable, so the returned pointer stays valid.
  it = g_loc_names.emplace(type, std::move(name)).first;
  return it->second.c_str();
}

// Slot +0x78 clones an action. The engine's own copy helper is reused so the
// per-instance state (actor, recipient, voter favours) is copied exactly the way
// stock actions do it; only the vtable is replaced with ours.
void* __fastcall OurClone(void* self) {
  if (self == nullptr || g_alloc == nullptr || g_copy_fn == nullptr ||
      g_resolved.action_size == 0) {
    return nullptr;
  }
  void* memory = g_alloc(g_resolved.action_size);
  if (memory == nullptr) return nullptr;
  g_copy_fn(memory, self);
  *static_cast<void**>(memory) = g_our_vtable;
  return memory;
}

template <typename T>
T At(uint32_t rva) {
  return reinterpret_cast<T>(g_module + rva);
}

bool Readable(const void* p, size_t size) {
  MEMORY_BASIC_INFORMATION mbi;
  if (p == nullptr || VirtualQuery(p, &mbi, sizeof(mbi)) == 0) return false;
  if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) {
    return false;
  }
  const uintptr_t start = reinterpret_cast<uintptr_t>(p);
  const uintptr_t region_end = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
  return start + size <= region_end;
}

// The name of an action type lives in a CString member at +0x10, whose inner
// std::string is the MSVC layout; CStringText already knows both offsets.
const char* TypeName(void* type) {
  return CStringText(static_cast<uint8_t*>(type) + 0x10);
}

// The token a scripted action name resolved to is baked in at construction time.
// If the hook was injected after the engine already parsed
// common/diplomatic_actions, those types still carry the sentinel 0xc from
// CStaticLexer::FindTok. This pass walks the database and repairs them, which is
// what makes the hook work no matter when it is injected.
//
// It is idempotent: registering an already known keyword returns its existing
// token, so stock actions are re-confirmed rather than changed.
bool CatchUpExistingTypes() {
  if (!g_resolved.ok || g_resolved.db_instance_ptr == 0 || g_add_dynamic_token == nullptr) {
    return false;
  }
  void* db = nullptr;
  if (!Readable(At<const void*>(g_resolved.db_instance_ptr), sizeof(void*))) {
    Log("catch-up: cannot read the action database pointer; skipped");
    return false;
  }
  memcpy(&db, At<const void*>(g_resolved.db_instance_ptr), sizeof(void*));
  if (db == nullptr) {
    Log("catch-up: action database not created yet; the constructor hook will "
        "handle every entry as it is loaded");
    return false;
  }
  if (!Readable(static_cast<uint8_t*>(db) + 0x50, 0x10)) {
    Log("catch-up: action database is not readable; skipped");
    return false;
  }
  uint32_t count = 0;
  void** entries = nullptr;
  memcpy(&count, static_cast<uint8_t*>(db) + 0x5c, 4);
  memcpy(&entries, static_cast<uint8_t*>(db) + 0x50, 8);
  if (count == 0 || count > 100000 || !Readable(entries, count * sizeof(void*))) {
    Log("catch-up: implausible action database (count=%u); skipped", count);
    return false;
  }

  int repaired = 0;
  int ours_seen = 0;
  for (uint32_t i = 0; i < count; ++i) {
    void* type = entries[i];
    if (!Readable(type, g_resolved.type_token_offset + 4)) continue;
    int token = 0;
    memcpy(&token, static_cast<uint8_t*>(type) + g_resolved.type_token_offset, 4);
    if (token != 0xc) {
      if (token > 0) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_our_tokens.count(token) != 0) ours_seen += 1;
      }
      continue;  // already had a real token
    }
    // Skip the engine's empty placeholder (the null object); it keeps 0xc.
    uint64_t name_length = 0;
    if (!CStringLength(static_cast<uint8_t*>(type) + 0x10, &name_length) ||
        name_length == 0) {
      continue;
    }
    const char* name = TypeName(type);
    int fresh = 0;
    {
      // Serialised with hook 1: see g_lexer_mutex.
      std::lock_guard<std::mutex> lexer_lock(g_lexer_mutex);
      fresh = g_add_dynamic_token(static_cast<uint8_t*>(type) + 0x10, true);
    }
    if (fresh <= 0) {
      Log("catch-up: could not register '%s'", name);
      continue;
    }
    memcpy(static_cast<uint8_t*>(type) + g_resolved.type_token_offset, &fresh, 4);
    {
      std::lock_guard<std::mutex> lock(g_mutex);
      g_our_tokens.insert(fresh);
    }
    repaired += 1;
    Log("catch-up: '%s' had no token; repaired to %d (0x%x)", name, fresh, fresh);
  }
  if (repaired == 0 && ours_seen == 0) {
    Log("catch-up: scanned %u action types, nothing to repair", count);
  } else {
    Log("catch-up: scanned %u action types, repaired %d, already registered %d", count,
        repaired, ours_seen);
  }
  return true;
}

// Exercises the exact call the diplomacy view makes for every action it wants to
// list: the patched CreateEmptyAction entry. A non-NULL object whose type carries
// the token we registered is what makes a new action usable, so this is the
// cheapest end-to-end proof that the whole chain works, without needing a game
// to be played.
void SelfTestGenericAction() {
  if (!g_resolved.ok || g_resolved.create_empty_action == 0) return;
  if (g_orig_create_empty_action == nullptr) {
    // Hook 2 is not in place, so that entry is still the engine's own factory:
    // calling it would report a failure for tokens it was never meant to handle.
    Log("self-test: the action factory is not hooked; skipped");
    return;
  }
  std::vector<int> ours;
  {
    std::lock_guard<std::mutex> lock(g_mutex);
    ours.assign(g_our_tokens.begin(), g_our_tokens.end());
  }
  if (ours.empty()) {
    Log("self-test: no new action names were registered, nothing to verify");
    return;
  }
  using Entry = void*(__fastcall*)(int);
  const Entry entry = At<Entry>(g_resolved.create_empty_action);
  if (!Readable(reinterpret_cast<const void*>(entry), 16)) {
    Log("self-test: the factory entry is not readable; skipped");
    return;
  }
  int passed = 0;
  for (int token : ours) {
    // MinGW has no SEH, so this relies on validation instead: the entry is the
    // real patched function, the token is one we registered, and both the
    // database lookup and the allocation were already exercised by the catch-up
    // pass above.
    void* object = entry(token);
    if (object == nullptr) {
      Log("self-test: FAILED, the factory returned NULL for token %d", token);
      continue;
    }
    void* type = nullptr;
    int type_token = -1;
    if (Readable(static_cast<uint8_t*>(object) + g_resolved.action_type_offset, 8)) {
      memcpy(&type, static_cast<uint8_t*>(object) + g_resolved.action_type_offset, 8);
      if (Readable(static_cast<uint8_t*>(type) + g_resolved.type_token_offset, 4)) {
        memcpy(&type_token,
               static_cast<uint8_t*>(type) + g_resolved.type_token_offset, 4);
      }
    }
    if (type_token == token) {
      passed += 1;
      Log("self-test: OK -- a generic diplomatic action object was built for token "
          "%d (0x%x), type confirmed", token, token);
      // Exercise the two calls ShowDiplomaticActions makes on every action it
      // wants to list. A missing derived vtable crashes right here with
      // "Pure Virtual Function Call", so running it proves the crash is gone.
      using SlotFn = bool(__fastcall*)(void*, int);
      const uint8_t* vtbl = *reinterpret_cast<const uint8_t* const*>(object);
      int slot_ok = 0;
      for (int slot : {0x48, 0x50}) {
        SlotFn fn = nullptr;
        if (!Readable(vtbl + slot, 8)) continue;
        memcpy(&fn, vtbl + slot, 8);
        if (fn == nullptr) continue;
        fn(object, 0);
        slot_ok += 1;
      }
      Log("self-test: called the diplomacy view's own check slots (%d/2) on the "
          "new action without incident", slot_ok);
      // Slot +0x70 supplies the localisation-key prefix the view will look the
      // action's text up under; showing it makes a missing translation obvious.
      using NameFn = const char*(__fastcall*)(void*);
      NameFn name_fn = nullptr;
      if (Readable(vtbl + 0x70, 8)) {
        memcpy(&name_fn, vtbl + 0x70, 8);
      }
      if (name_fn != nullptr) {
        const char* prefix = name_fn(object);
        Log("self-test: localisation keys will be looked up as '<prefix>_TITLE', "
            "'<prefix>_DESC', ... with prefix '%s'",
            prefix != nullptr ? prefix : "(null)");
      }
    } else {
      Log("self-test: FAILED, token %d produced an object whose type token is %d",
          token, type_token);
    }
  }
  Log("self-test: %d of %zu newly registered action(s) verified through the "
      "factory the diplomacy view uses", passed, ours.size());
  if (passed > 0) {
    Log("the new action(s) are in the database with a valid token and can be "
        "constructed; open a diplomacy window to see them listed");
  }
}

// A late-injected hook can miss the initial load entirely, so the database is
// revisited a few times instead of only once, and one pass after the data has
// loaded runs a self-test of the factory path the diplomacy view uses.
DWORD WINAPI CatchUpWorker(void*) {
  int verified_at = -1;
  for (int attempt = 0; attempt < 40; ++attempt) {
    Sleep(attempt == 0 ? 300 : (attempt < 10 ? 2000 : 8000));
    const bool saw_db = CatchUpExistingTypes();
    if (saw_db && verified_at < 0) {
      verified_at = attempt;
      SelfTestGenericAction();
    }
    if (verified_at >= 0) {
      Log("verification complete; monitoring stopped");
      return 0;
    }
  }
  Log("verification: the action database never appeared; the constructor hook "
      "will still register names as they load");
  return 0;
}

// Repairing the entries that were already loaded is hook 1's job, so this runs
// whenever hook 1 is in place; the self-test inside it is skipped when hook 2
// could not be installed.
void StartCatchUp() {
  HANDLE thread = CreateThread(nullptr, 0, CatchUpWorker, nullptr, 0, nullptr);
  if (thread != nullptr) {
    CloseHandle(thread);
  } else {
    Log("WARNING: could not start the catch-up thread");
  }
}

}  // namespace

bool ResolveOnly() {
  const HMODULE module = GetModuleHandleA(nullptr);
  g_module = reinterpret_cast<uintptr_t>(module);

  char path[MAX_PATH] = {0};
  GetModuleFileNameA(module, path, MAX_PATH);
  Log("host module: %s @ 0x%llx", path, static_cast<unsigned long long>(g_module));

  anchor::Image image;
  if (!image.InitFromMapped(reinterpret_cast<const uint8_t*>(module))) {
    Log("FAILED: could not parse the host module as a PE image");
    return false;
  }
  Log("image base 0x%llx, %zu sections, %zu functions in .pdata",
      static_cast<unsigned long long>(image.image_base()), image.sections().size(),
      image.Functions().size());

  ResolveAll(image, &g_resolved);
  if (!g_resolved.ok) {
    Log("FAILED: address resolution stopped at: %s", g_resolved.failure);
    Log("Nothing was hooked; the game is untouched.");
    return false;
  }
  Log("resolved:");
  Log("  CDiplomaticActionType::CDiplomaticActionType  rva 0x%08x", g_resolved.type_ctor);
  Log("  CStaticLexer::AddDynamicToken                rva 0x%08x",
      g_resolved.add_dynamic_token);
  Log("  CStaticLexer singleton accessor              rva 0x%08x", g_resolved.lexer_accessor);
  Log("  CDiplomacyView::ShowDiplomaticActions        rva 0x%08x", g_resolved.diplo_view);
  Log("  NDiplomacyUtil::CreateDiplomaticAction       rva 0x%08x",
      g_resolved.create_diplo_action);
  Log("  CreateEmptyAction                            rva 0x%08x",
      g_resolved.create_empty_action);
  Log("  operator new                                 rva 0x%08x", g_resolved.alloc);
  Log("  CDiplomaticAction::CDiplomaticAction(int)    rva 0x%08x", g_resolved.base_ctor);
  Log("  CDiplomaticAction vtable                     rva 0x%08x", g_resolved.base_vtable);
  Log("  action type database pointer variable        rva 0x%08x",
      g_resolved.db_instance_ptr);
  Log("  sizeof(CDiplomaticAction) = 0x%x, token field +0x%x, type field +0x%x",
      g_resolved.action_size, g_resolved.type_token_offset, g_resolved.action_type_offset);
  return true;
}

bool InstallHooks() {
  if (!ResolveOnly()) return false;

  g_add_dynamic_token = At<AddDynamicTokenFn>(g_resolved.add_dynamic_token);
  g_alloc = At<AllocFn>(g_resolved.alloc);
  g_base_ctor = At<BaseCtorFn>(g_resolved.base_ctor);
  if (g_resolved.copy_fn != 0) {
    g_copy_fn = At<CopyFn>(g_resolved.copy_fn);
  }

  // Build the concrete vtable for synthesized actions. The base vtable's slots
  // are copied verbatim and only the pure ones are replaced, so every other
  // behaviour stays exactly what the base class implements. A build whose shape
  // does not match is reported, and hook 1 still goes in on its own: it does not
  // depend on the vtable, and it is what gives scripted names real tokens.
  bool vtable_ready = false;
  if (g_resolved.pure_slot_count != 2 || g_resolved.pure_slots[0] != 0x70 ||
      g_resolved.pure_slots[1] != 0x78) {
    Log("WARNING: CDiplomaticAction has %u pure virtual slot(s) (%s); this build "
        "is not the shape this hook was verified against, so new actions will "
        "load with a valid token but will not be offered in the diplomacy view",
        g_resolved.pure_slot_count,
        g_resolved.pure_slot_count > 0 ? "see slots below" : "none found");
    for (uint32_t i = 0; i < g_resolved.pure_slot_count && i < 4; ++i) {
      Log("  pure slot +0x%x", g_resolved.pure_slots[i]);
    }
  } else {
    const uint8_t* base = At<const uint8_t*>(g_resolved.base_vtable);
    size_t slot = 0;
    for (uint32_t off = 0; off < kMaxVtableSlots * 8; off += 8, ++slot) {
      uint64_t value = 0;
      if (!Readable(base + off, 8)) break;
      memcpy(&value, base + off, 8);
      g_our_vtable[slot] = static_cast<uintptr_t>(value);
    }
    g_our_vtable[0x70 / 8] = reinterpret_cast<uintptr_t>(&OurGetLocName);
    g_our_vtable[0x78 / 8] = reinterpret_cast<uintptr_t>(&OurClone);
    Log("concrete action vtable built at 0x%llx: base slots copied, "
        "+0x70 -> localisation prefix from the type name, +0x78 -> clone",
        static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(g_our_vtable)));
    if (g_copy_fn == nullptr) {
      Log("WARNING: the engine's action copy helper was not located; cloning a "
          "new action will return nothing");
    }
    vtable_ready = true;
  }

  const char* reason = "";
  if (!g_hook_type_ctor.Install(At<void*>(g_resolved.type_ctor),
                               reinterpret_cast<void*>(&HookTypeCtor), &reason)) {
    Log("FAILED: could not hook the action-type constructor: %s", reason);
    return false;
  }
  g_orig_type_ctor = reinterpret_cast<TypeCtorFn>(g_hook_type_ctor.trampoline());
  Log("hook 1 installed (stole %zu prologue bytes): scripted action names now get "
      "real keyword tokens", g_hook_type_ctor.stolen());

  bool factory_ready = false;
  if (vtable_ready) {
    reason = "";
    if (!g_hook_create_empty_action.Install(At<void*>(g_resolved.create_empty_action),
                                            reinterpret_cast<void*>(&HookCreateEmptyAction),
                                            &reason)) {
      Log("WARNING: could not hook the action factory: %s", reason);
      Log("New actions will load with a valid token but will not appear in the "
          "diplomacy view.");
    } else {
      g_orig_create_empty_action =
          reinterpret_cast<CreateEmptyActionFn>(g_hook_create_empty_action.trampoline());
      factory_ready = true;
      Log("hook 2 installed (stole %zu prologue bytes): new tokens now produce a "
          "generic scripted action", g_hook_create_empty_action.stolen());
    }
  }

  // Anything loaded before hook 1 existed gets repaired in the background, so the
  // result does not depend on how early the injection happened. That repair is
  // hook 1's work, which is why it also runs when hook 2 could not be installed.
  StartCatchUp();

  if (factory_ready) {
    Log("ready -- define 'action_<your name> = { ... }' under "
        "common/diplomatic_actions/ and it will load as a real diplomatic action");
  } else {
    Log("partial -- action names get real tokens, but no action object will be "
        "built for them");
  }
  return true;
}

}  // namespace diplo
