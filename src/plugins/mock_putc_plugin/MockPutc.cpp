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
#include "icemu/hooks/HookFunction.h"
#include "icemu/hooks/HookManager.h"
#include "icemu/hooks/RegisterHook.h"
#include "icemu/emu/Function.h"


using namespace std;
using namespace icemu;

class MockPutc : public HookFunction {

 public:
  // Always execute
  MockPutc(Emulator &emu, string fname) : HookFunction(emu, fname) {}

  ~MockPutc() {
  }

  // Hook run
  void run(hook_arg_t *arg) {
    (void)arg;
    Registers &reg = getRegisters();

    Function::Argument<char> farg_char;
    Function::Argument<uint32_t> farg_file; // Unused
    Function::Arguments::parse(reg, farg_char, farg_file);

    cout << farg_char.arg;

    Function::skip(reg, farg_char.arg);
  }
};

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  auto mf = new MockPutc(emu, "putc");
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
