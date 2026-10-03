// Resolves every game address the hook needs, starting only from unique string
// literals, and derives the object layout from the code that touches it. No RVA
// and no field offset is hardcoded for a specific build, so the same binary works
// on any build whose strings and call shapes are unchanged: verified on 4.5.0,
// 4.5.1, 4.2.4 and 3.14.1592653.
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

  // Object field offsets. The token offset is derived (it moves between builds);
  // `action_type_offset` is the same 0x40 on every build seen and is checked by
  // the hook's own self-test.
  uint32_t type_token_offset = 0;     // token inside CDiplomaticActionType
  uint32_t action_type_offset = 0x40; // CDiplomaticAction::_type
  uint32_t action_size = 0;           // bytes to allocate for a generic action
  uint32_t action_size_from_ctor = 0; // what the constructor itself writes
  uint32_t action_size_upper_bound = 0;  // largest class size in the dispatch

  // Layout of the action-type database the base constructor searches, read off
  // that constructor's own inlined lookup rather than fixed: entries at +0x50
  // and count at +0x5c on 4.5, +0x40 and +0x4c on 4.2.4 and 3.14.
  uint32_t db_entries_offset = 0x50;
  uint32_t db_count_offset = 0x5c;

  // The lexer's token counters, read off CStaticLexer::AddDynamicToken. The
  // static keyword count is the higher of the two; they are 0x20 apart on every
  // build seen so far, at +0x84/+0x64 on 4.5 and 4.2.4 and +0x7c/+0x5c on 3.14.
  uint32_t lexer_static_offset = 0x84;
  uint32_t lexer_dynamic_offset = 0x64;

  // Where the action name sits inside the type, and where the text lives inside
  // that name object. The member offset is 0x10 on every build seen; the string
  // inside it is at +0x10 on 4.5 but at +0x00 on 4.2.4 and 3.14, so it is read
  // off AddDynamicToken (see FindNameDataOffset).
  uint32_t name_member_offset = 0x10;
  uint32_t name_data_offset = 0x10;

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

  // The AI's "do you want to propose this?" gate. The base class answers 0 for
  // every action it is not specialised for, which is why a synthesized action is
  // only ever player-initiated. |scripted_ai_propose| is the engine's own
  // CDiplomaticAction::ScriptedShouldAIPropose(), i.e. the function that
  // evaluates the action's `should_ai_propose` mean-time-to-happen;
  // |ai_propose_slot| is the vtable offset the AI asks the question through.
  // Both stay 0 -- and the hook then leaves the feature out -- when they cannot
  // be derived with confidence; |ai_propose_failure| says why.
  uint32_t scripted_ai_propose = 0;
  uint32_t ai_propose_slot = 0;
  uint32_t ai_propose_votes = 0;  // stock vtables that agreed on the slot
  const char* ai_propose_failure = "not attempted";

  // The AI's acceptance score. GetAIAcceptance() decides how willing the
  // recipient is, but its per-token table cannot have a case for a token this
  // DLL invented, so a new action scores only its scripted `ai_acceptance` field.
  // The hook adds |ai_acceptance_base_offset|'s int -- the setting
  // `AI_acceptance_base_value`, which every stock action gets from that table --
  // for tokens this DLL created. Same rule as above: zero means "not located,
  // leave the feature out".
  uint32_t scripted_acceptance = 0;        // GetScriptedAcceptance(action, CString*)
  uint32_t get_ai_acceptance = 0;          // GetAIAcceptance(action, int, CString*)
  uint32_t ai_acceptance_base_offset = 0;  // int `AI_acceptance_base_value` in the type
  const char* ai_acceptance_failure = "not attempted";

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
