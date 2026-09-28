// The detours that make script-defined diplomatic actions usable.
//
//  1. CDiplomaticActionType::CDiplomaticActionType(int, CString const&)
//     The token of a scripted action is not derived from its name -- it is
//     looked up in a build-time keyword table, and an unknown name yields the
//     sentinel 0xc ("num"). Registering the name through the engine's own
//     CStaticLexer::AddDynamicToken first gives the action a real token.
//
//  2. CreateEmptyAction(int)
//     The runtime action object is chosen by a hardcoded switch on the token and
//     is NULL for anything it does not know. For tokens this hook created, a
//     plain CDiplomaticAction is constructed instead; its behaviour
//     (potential / possible / proposable / on_propose / on_accept / on_decline)
//     is entirely script-driven, so the new action works like a native one.
//
// and, on the object that factory hands out, one synthesized virtual:
//
//  3. ShouldAIPropose(int) -- vtable slot resolved at runtime
//     The base implementation returns a flat 0, so an unspecialised action is
//     never proposed by an AI empire. The slot is pointed at the engine's own
//     CDiplomaticAction::ScriptedShouldAIPropose, which evaluates the action's
//     `should_ai_propose` block -- the same call every stock subclass makes.
//
// plus one detour that gives the synthesized action the acceptance value the
// engine keeps in a per-token table for its own actions:
//
//  4. GetAIAcceptance(CDiplomaticAction const*, int, CString*)
//     For a token the engine has no case for, the score is only the scripted
//     `ai_acceptance` field. `AI_acceptance_base_value` -- which every stock
//     action reads from that table -- is added to the returned score here, and
//     only for tokens this DLL created.
#pragma once

namespace diplo {

// Resolves every address and writes the result to the log, without hooking
// anything. This is what probe-only mode runs.
bool ResolveOnly();

// Resolves addresses and installs both hooks. Safe to call once; returns true
// when the token-registration hook is in place (the factory hook may still have
// failed, which is reported in the log).
bool InstallHooks();

}  // namespace diplo
