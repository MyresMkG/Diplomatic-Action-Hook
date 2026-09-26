// DLL entry point.
//
// Everything interesting happens on a worker thread: DllMain runs under the
// loader lock, and installing hooks there could deadlock the game's own startup.
#include <windows.h>

#include <string>

#include "game_hooks.h"
#include "log.h"

namespace {

HMODULE g_self = nullptr;

// When a file with this name sits next to the DLL, the hook only resolves and
// reports addresses. Useful for checking a game build before trusting it. Both
// the DLL's own path and the flag are wide: a directory the ANSI code page
// cannot spell would otherwise make the flag invisible.
bool ProbeOnly() {
  wchar_t path[1024] = {0};
  const DWORD n = GetModuleFileNameW(g_self, path, ARRAYSIZE(path));
  if (n == 0 || n >= ARRAYSIZE(path)) {
    diplo::Log("cannot tell where this DLL lives; assuming the probe flag is unset");
    return false;
  }
  const std::wstring file(path, n);
  const size_t slash = file.find_last_of(L"\\/");
  const std::wstring dir =
      (slash == std::wstring::npos) ? std::wstring(L".") : file.substr(0, slash);
  const std::wstring flag = dir + L"\\diplo_action_hook_probe_only.txt";
  return GetFileAttributesW(flag.c_str()) != INVALID_FILE_ATTRIBUTES;
}

DWORD WINAPI Worker(void*) {
  diplo::LogInit(g_self);
  if (ProbeOnly()) {
    diplo::Log("probe-only mode: resolving addresses, nothing will be hooked");
    if (diplo::ResolveOnly()) {
      diplo::Log("probe finished: every address resolved; the hook would install");
    } else {
      diplo::Log("probe finished: resolution failed, see above");
    }
    diplo::Log("delete diplo_action_hook_probe_only.txt to enable the hook");
    return 0;
  }
  diplo::Log("diplo_action_hook attaching");
  if (!diplo::InstallHooks()) {
    diplo::Log("hook installation did not complete; see the messages above");
    return 1;
  }
  diplo::Log("attach complete");
  return 0;
}

}  // namespace

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    g_self = instance;
    DisableThreadLibraryCalls(instance);
    HANDLE thread = CreateThread(nullptr, 0, Worker, nullptr, 0, nullptr);
    if (thread != nullptr) CloseHandle(thread);
  }
  return TRUE;
}
