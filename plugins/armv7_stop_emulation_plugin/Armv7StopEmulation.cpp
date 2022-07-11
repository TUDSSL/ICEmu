/**
 *  ICEmu loadable plugin (library)
 *
 * Should be compiled as a shared library, i.e. using `-shared -fPIC`
 */
#include <iostream>

#include "icemu/emu/Emulator.h"
#include "icemu/hooks/HookCode.h"
#include "icemu/hooks/HookManager.h"
#include "icemu/hooks/RegisterHook.h"

using namespace std;
using namespace icemu;

class Armv7StopEmulation : public HookCode {
 private:
  // Stop emulation when we reach a breakpoint instruction
  const uint16_t breakpoint_instr = 0xbe00; 

 public:
  Armv7StopEmulation(Emulator &emu) : HookCode(emu, "armv7_stop_emulation") {
  }

  // Hook run
  void run(hook_arg_t *arg) {
    uint16_t instr;
    if (getEmulator().readMemory(arg->address, (char *)&instr, sizeof(instr))) {
      if (instr == breakpoint_instr) {
        getEmulator().stop("Breakpoint instruction");
        setStatus(Hook::STATUS_SKIP_REST);
      }
    } else {
      std::cerr << "Could not read instruction memory" << std::endl;
      getEmulator().stop("Could not read instruction");
      setStatus(Hook::STATUS_SKIP_REST);
    }
  }
};

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  HM.add(new Armv7StopEmulation(emu));
}

// Class that is used by ICEmu to finf the register function
// NB.  * MUST BE NAMED "RegisterMyHook"
//      * MUST BE global
RegisterHook RegisterMyHook(registerMyCodeHook);
