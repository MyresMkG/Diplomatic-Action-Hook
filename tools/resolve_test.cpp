// Host-side harness that runs the same address resolution the DLL performs,
// against a game executable on disk. Lets the resolver be checked without
// launching the game.
//
// usage: resolve_test.exe <stellaris.exe>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "../src/anchor.h"
#include "../src/resolver.h"

// Expected values are supplied as arguments so the same harness can be pointed
// at different builds; pass "-" to skip a check.
static int Check(const char* name, uint32_t got, const char* expect) {
  if (strcmp(expect, "-") == 0) {
    printf("  %-44s 0x%08x (no expectation)\n", name, got);
    return 0;
  }
  const uint32_t want = static_cast<uint32_t>(strtoul(expect, nullptr, 0));
  const bool ok = got == want;
  printf("  %-44s 0x%08x  expected 0x%08x  %s\n", name, got, want, ok ? "OK" : "MISMATCH");
  return ok ? 0 : 1;
}

int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr,
            "usage: %s <stellaris.exe> [type_ctor add_dyn lexer view helper factory "
            "alloc ctor vtable size ai_propose gate_slot scripted_acceptance scorer "
            "acceptance_base_offset]\n",
            argv[0]);
    return 2;
  }
  anchor::Image image;
  if (!image.InitFromFile(argv[1])) {
    fprintf(stderr, "cannot load %s\n", argv[1]);
    return 2;
  }
  printf("image %s\n  base=0x%llx sections=%zu functions=%zu\n", argv[1],
         static_cast<unsigned long long>(image.image_base()), image.sections().size(),
         image.Functions().size());

  diplo::Resolved r;
  diplo::ResolveAll(image, &r);
  printf("resolved=%d failure=%s\n", r.ok ? 1 : 0, r.failure);
  if (!r.ok) return 1;

  const char* e[15] = {"-", "-", "-", "-", "-", "-", "-", "-", "-", "-",
                       "-", "-", "-", "-", "-"};
  for (int i = 0; i < 15 && i + 2 < argc; ++i) e[i] = argv[i + 2];

  int bad = 0;
  bad += Check("CDiplomaticActionType constructor", r.type_ctor, e[0]);
  bad += Check("CStaticLexer::AddDynamicToken", r.add_dynamic_token, e[1]);
  bad += Check("lexer singleton accessor", r.lexer_accessor, e[2]);
  bad += Check("CDiplomacyView::ShowDiplomaticActions", r.diplo_view, e[3]);
  bad += Check("NDiplomacyUtil::CreateDiplomaticAction", r.create_diplo_action, e[4]);
  bad += Check("CreateEmptyAction", r.create_empty_action, e[5]);
  bad += Check("operator new", r.alloc, e[6]);
  bad += Check("CDiplomaticAction::ctor(int)", r.base_ctor, e[7]);
  bad += Check("CDiplomaticAction vtable", r.base_vtable, e[8]);
  if (strcmp(e[9], "-") == 0) {
    printf("  %-44s 0x%x (no expectation)\n", "sizeof(CDiplomaticAction)", r.action_size);
  } else {
    bad += Check("sizeof(CDiplomaticAction)", r.action_size, e[9]);
  }
  bad += Check("CDiplomaticAction::ScriptedShouldAIPropose", r.scripted_ai_propose, e[10]);
  bad += Check("ShouldAIPropose vtable slot", r.ai_propose_slot, e[11]);
  bad += Check("GetScriptedAcceptance", r.scripted_acceptance, e[12]);
  bad += Check("GetAIAcceptance", r.get_ai_acceptance, e[13]);
  bad += Check("AI_acceptance_base_value offset", r.ai_acceptance_base_offset, e[14]);
  printf("  %-44s %u stock vtables agreed\n", "AI propose gate agreement",
         r.ai_propose_votes);
  printf("  %-44s %s\n", "AI propose gate status", r.ai_propose_failure);
  printf("  %-44s %s\n", "AI acceptance status", r.ai_acceptance_failure);
  printf("  %-44s 0x%08x\n", "action type DB pointer variable", r.db_instance_ptr);
  printf("  %-44s 0x%08x (%u slots: 0x%x, 0x%x)\n", "_purecall stub", r.purecall,
         r.pure_slot_count, r.pure_slots[0], r.pure_slots[1]);
  printf("  %-44s 0x%08x\n", "engine action copy helper", r.copy_fn);
  printf("  %-44s 0x%x (inside the name object)\n", "action name data offset",
         r.name_data_offset);
  printf("  %-44s 0x%x (inside the action type)\n", "action name member offset",
         r.name_member_offset);
  printf("  %-44s 0x%x / 0x%x\n", "lexer counters (static/dynamic)",
         r.lexer_static_offset, r.lexer_dynamic_offset);
  printf("  %-44s 0x%x / 0x%x\n", "database entries/count offset",
         r.db_entries_offset, r.db_count_offset);
  printf("%s\n", bad == 0 ? "ALL CHECKS PASSED" : "*** CHECKS FAILED ***");
  return bad == 0 ? 0 : 1;
}
