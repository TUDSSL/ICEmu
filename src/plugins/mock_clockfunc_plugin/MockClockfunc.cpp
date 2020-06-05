/**
 *  ICEmu loadable plugin (library)
 *
 * An example ICEmu plugin that is dynamically loaded.
 * This example prints the address of each instruction that is executed.
 *
 * Should be compiled as a shared library, i.e. using `-shared -fPIC`
 */
#include <iostream>

#include "icemu/emu/Emulator.h"
#include "icemu/hooks/HookFunction.h"
#include "icemu/hooks/HookManager.h"
#include "icemu/hooks/RegisterHook.h"
#include "icemu/emu/Function.h"

using namespace std;
using namespace icemu;

// TODO: Need a way to get information from other hooks
class HookInstructionCount : public HookCode {
 public:
  uint64_t icnt = 0;

  HookInstructionCount(Emulator &emu) : HookCode(emu, "icnt-clock") {
  }

  ~HookInstructionCount() {
    //std::cout << "The program ran for: " << icnt << " instructions" << std::endl;
  }

  void run(hook_arg_t *arg) {
    (void)arg;  // Don't care
    ++icnt;
  }
};


class MockClockfunc : public HookFunction {
 public:
  HookInstructionCount *hook_instr_cnt;

  // Always execute
  MockClockfunc(Emulator &emu, string fname) : HookFunction(emu, fname) {
    hook_instr_cnt = new HookInstructionCount(emu);
  }

  ~MockClockfunc() {
  }

  // Hook run
  void run(hook_arg_t *arg) {
    (void)arg;
    Registers &reg = getRegisters();
    Function::setReturn64(reg, hook_instr_cnt->icnt);
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
  HM.add(mf->hook_instr_cnt);
}

// Class that is used by ICEmu to finf the register function
// NB.  * MUST BE NAMED "RegisterMyHook"
//      * MUST BE global
RegisterHook RegisterMyHook(registerMyCodeHook);
