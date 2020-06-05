/**
 *  ICEmu loadable plugin (library)
 *
 * An example ICEmu plugin that is dynamically loaded.
 * This example prints the address of each instruction that is executed.
 *
 * Should be compiled as a shared library, i.e. using `-shared -fPIC`
 */
#include <iostream>
#include <chrono>

#include "icemu/emu/Emulator.h"
#include "icemu/hooks/HookFunction.h"
#include "icemu/hooks/HookManager.h"
#include "icemu/hooks/RegisterHook.h"
#include "icemu/emu/Function.h"

#include "icemu/util/ElapsedTime.h"

using namespace std;
using namespace icemu;


class MockClockfunc : public HookFunction {
 public:
  ElapsedTime etime;

  // Always execute
  MockClockfunc(Emulator &emu, string fname) : HookFunction(emu, fname) {
    etime.start(); // We already have this class, so lets just use this
  }

  ~MockClockfunc() {
  }

  // Hook run
  void run(hook_arg_t *arg) {
    (void)arg;
    Registers &reg = getRegisters();
    // We configured the coremark 'core_portme.c' EE_TICKS_PER_SEC to 10MHz.
    // So that is 100ns per tick.
    // As such we get the time in ns and devide it by 100
    etime.stop();
    uint64_t current_tick = etime.get_ns()/100;

    Function::setReturn64(reg, current_tick);
    Function::skip(reg);
  }
};

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  auto mf = new MockClockfunc(emu, "clock");
  if (mf->getStatus() == Hook::STATUS_ERROR) {
    delete mf;
    return;
  }
  HM.add(mf);
}

// Class that is used by ICEmu to finf the register function
// NB.  * MUST BE NAMED "RegisterMyHook"
//      * MUST BE global
RegisterHook RegisterMyHook(registerMyCodeHook);
