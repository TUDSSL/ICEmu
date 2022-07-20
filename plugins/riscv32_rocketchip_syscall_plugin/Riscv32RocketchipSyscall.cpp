/**
 *  ICEmu loadable plugin (library)
 *
 * Copy of the 64-bit version but with 32-bit writes
 */
#include <iostream>
#include <string.h>

#include "icemu/emu/Emulator.h"
#include "icemu/hooks/HookFunction.h"
#include "icemu/hooks/HookManager.h"
#include "icemu/hooks/RegisterHook.h"

#include "PluginArgumentParsing.h"

#include "RiscvXXRocketchipSyscall.h"

using namespace std;
using namespace icemu;

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  auto p = new RiscvXXRocketchipSyscall<uint32_t>(emu); // 32-bit version
  if (p->good) {
    HM.add(p);
  } else {
    delete p;
  }
}

// Class that is used by ICEmu to finf the register function
// NB.  * MUST BE NAMED "RegisterMyHook"
//      * MUST BE global
RegisterHook RegisterMyHook(registerMyCodeHook);
