// Resolves every game address the hook needs, starting only from unique string
// literals. No RVA is hardcoded, so the same binary works on any build whose
// strings are unchanged (verified on 4.5.0 and 4.5.1).
#pragma once

#include <cstdint>

#include "anchor.h"

namespace diplo {

struct Resolved {
  bool ok = false;
  const char* failure = "";

  // Directly anchored entry points.
  uint32_t type_ctor = 0;           // CDiplomaticActionType::CDiplomaticActionType(int, CString const&)
  uint32_t add_dynamic_token = 0;   // CStaticLexer::AddDynamicToken(CString const&, bool)
  uint32_t lexer_accessor = 0;      // returns the CStaticLexer singleton

  // Reached through the diplomacy-view call chain.
  uint32_t diplo_view = 0;          // CDiplomacyView::ShowDiplomaticActions
  uint32_t create_diplo_action = 0; // NDiplomacyUtil::CreateDiplomaticAction
  uint32_t create_empty_action = 0; // CreateEmptyAction(int)

  // Reached from inside CreateEmptyAction / the base constructor.
  uint32_t alloc = 0;         // operator new(size_t)
  uint32_t base_ctor = 0;     // CDiplomaticAction::CDiplomaticAction(int)
  uint32_t base_vtable = 0;   // vtable CDiplomaticAction::CDiplomaticAction installs

  // Object field offsets, re-derived rather than assumed.
  uint32_t type_token_offset = 0x50;  // token inside CDiplomaticActionType
  uint32_t action_type_offset = 0x40; // CDiplomaticAction::_type
  uint32_t action_size = 0;           // bytes to allocate for a generic action
  uint32_t action_size_from_ctor = 0; // what the constructor itself writes
  uint32_t action_size_upper_bound = 0;  // largest class size in the dispatch

  // The action-type database singleton pointer variable, used by the catch-up
  // pass that repairs actions created before the hook was installed.
  uint32_t db_instance_ptr = 0;

  // CDiplomaticAction is an abstract class: its own vtable leaves two slots as
  // MSVC's _purecall stub, and the engine never installs it as a final vtable.
  // |purecall| is that stub's address, and |pure_slots| are the vtable offsets
  // that hold it (verified to be exactly 0x70 and 0x78).
  uint32_t purecall = 0;
  uint32_t pure_slots[4] = {0, 0, 0, 0};
  uint32_t pure_slot_count = 0;

  // The engine's own "copy one action into another" helper, taken from a stock
  // concrete class's clone virtual, so the synthesized class can clone too.
  uint32_t copy_fn = 0;

  // Token-space boundary, read lazily once the lexer exists.
  uint32_t static_token_count = 0;
};

// Fills |out| from the image. Never throws; on failure |out.ok| is false and
// |out.failure| explains the first missing step.
void ResolveAll(const anchor::Image& img, Resolved* out);

// Reads the static/dynamic token counters out of the lexer singleton. Safe to
// call only once the lexer has been initialised (i.e. after the first
// CDiplomaticActionType construction).
bool ReadTokenCounts(const Resolved& r, uint32_t* static_count, uint32_t* dynamic_count);

}  // namespace diplo
