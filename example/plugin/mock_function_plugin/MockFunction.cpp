/**
 *  ICEmu loadable plugin (library)
 *
 * An example ICEmu plugin that is dynamically loaded.
 * This example prints the address of each instruction that is executed.
 *
 * Should be compiled as a shared library, i.e. using `-shared -fPIC`
 */
#include <iostream>
#include <regex>
#include <cstdlib>
#include <atomic>

#include "icemu/emu/Emulator.h"
#include "icemu/emu/Architecture.h"
#include "icemu/hooks/HookFunction.h"
#include "icemu/hooks/HookManager.h"
#include "icemu/hooks/RegisterHook.h"


using namespace std;
using namespace icemu;


class MockFunction : public HookFunction {

 public:
  // Always execute
  MockFunction(Emulator &emu, string fname)
      : HookFunction(emu, fname) {}

  ~MockFunction() {
  }

  // Hook run
  void run(hook_arg_t *arg) {
    cout << "Func: " << function_name << " at: " << arg->address << endl;

    auto arch = getEmulator().getArchitecture();

    address_t arg0 = arch.functionGetArgument(0);
    address_t arg1 = arch.functionGetArgument(1);

    cout << "  Argument: " << arg0 << ", " << arg1 << endl;

    // Get generic registers
    address_t sp = arch.registerGet(Architecture::REG_SP);
    cout << "  SP register: " << sp << endl;

    // Skip the rest of the function
    arch.functionSetReturn((uint16_t)42);
    arch.functionSkip();
  }
};

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  auto mf = new MockFunction(emu, "call_simple");
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
