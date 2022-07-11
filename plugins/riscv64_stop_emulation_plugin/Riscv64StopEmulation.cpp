/**
 *  ICEmu loadable plugin (library)
 *
 * Should be compiled as a shared library, i.e. using `-shared -fPIC`
 */
#include <iostream>

#include "icemu/emu/Emulator.h"
#include "icemu/hooks/HookFunction.h"
#include "icemu/hooks/HookManager.h"
#include "icemu/hooks/RegisterHook.h"

using namespace std;
using namespace icemu;

class Riscv64StopEmulation : public HookFunction {
 public:
  Riscv64StopEmulation(Emulator &emu) : HookFunction(emu, "tohost_exit") {
  }

  // Hook run
  void run(hook_arg_t *arg) {
    (void)arg;
    getEmulator().stop("reached tohost_exit");
    setStatus(Hook::STATUS_SKIP_REST);
  }
};

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  HM.add(new Riscv64StopEmulation(emu));
}

// Class that is used by ICEmu to finf the register function
// NB.  * MUST BE NAMED "RegisterMyHook"
//      * MUST BE global
RegisterHook RegisterMyHook(registerMyCodeHook);
