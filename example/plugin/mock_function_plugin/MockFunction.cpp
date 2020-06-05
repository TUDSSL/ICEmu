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

    //cout << "Registers:" << endl;
    //getEmulator().getRegisters().dump(cout);
    Function::Argument<uint32_t> farg1;
    // Example changing the parse lambda function:
    //farg1.parse = [&farg1](const char *virtregbuff) {
    //  std::cout << "Copy" << std::endl;
    //  memcpy((void *)&farg1.arg, virtregbuff, farg1.size);
    //};
    Function::Argument<uint16_t> farg2;
    Function::Arguments::parse(getRegisters(), farg1, farg2);

    cout << "  Argument: " << farg1.arg << ", " << farg2.arg << endl;

    Function::setReturn(getRegisters(), 42);
    Function::skip(getRegisters());
    // Same as:
    // Function::skip(getRegisters(), 42);
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
