/**
 *  ICEmu loadable plugin (library)
 *
 * An example ICEmu plugin that is dynamically loaded.
 * This example prints the address of each instruction that is executed.
 *
 * Should be compiled as a shared library, i.e. using `-shared -fPIC`
 */
#include <iostream>
#include <vector>

#include "capstone/capstone.h"

#include "icemu/emu/Emulator.h"
#include "icemu/hooks/HookCode.h"
#include "icemu/hooks/HookManager.h"
#include "icemu/hooks/RegisterHook.h"

#include "CycleCounter.h"

using namespace std;
using namespace icemu;


class CycleCount : public HookCode {
 private:
  //Pipeline pipeline;
  CycleCounter cycleCounter;

 public:
  // Always execute
  CycleCount(Emulator &emu) : HookCode(emu, "cycle_count"), cycleCounter(emu) {
  }

  ~CycleCount() {
    cout << "The program ran for: " << cycleCounter.cycleCount() << " clock cycles (estimate)" << endl;
  }

  // Hook run
  void run(hook_arg_t *arg) {
    cycleCounter.add(arg->address, arg->size);
  }
};

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  HM.add(new CycleCount(emu));
}

// Class that is used by ICEmu to finf the register function
// NB.  * MUST BE NAMED "RegisterMyHook"
//      * MUST BE global
RegisterHook RegisterMyHook(registerMyCodeHook);
