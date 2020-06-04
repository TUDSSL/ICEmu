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
#include "icemu/hooks/HookCode.h"
#include "icemu/hooks/HookManager.h"
#include "icemu/hooks/RegisterHook.h"
#include "icemu/emu/FunctionArgs.h"


using namespace std;
using namespace icemu;


class MockFunction : public HookCode {
 private:
  string printLeader() {
    return "(icemu) ";
  }

  string func_name;

 public:
  // Always execute
  MockFunction(Emulator &emu, string fname)
      : HookCode(emu, "mock_function_" + fname,
                 emu.getMemory().getSymbols().get(fname)->getFuncAddr()),
        func_name(fname) {}

  ~MockFunction() {
  }

  // Hook run
  void run(hook_arg_t *arg) {
    cout << "Func: " << func_name << " at: " << arg->address << endl;

    //cout << "Registers:" << endl;
    //getEmulator().getRegisters().dump(cout);
    FunctionArg<uint32_t> farg1;
    //farg1.parse = [&farg1](const char *virtregbuff) {
    //  std::cout << "Copy" << std::endl;
    //  memcpy((void *)&farg1.arg, virtregbuff, farg1.size);
    //};
    FunctionArg<uint16_t> farg2;
    FunctionArgs::parse(getEmulator().getRegisters(), farg1, farg2);

    cout << "  Argument: " << farg1.arg << ", " << farg2.arg << endl;
  }
};

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  std::string fname = "call_simple";
  try {
    auto mf = new MockFunction(emu, fname);
    HM.add(mf);
  } catch (...) {
    cerr << "Failed to register mock hook for:" << fname << endl;
  }
}

// Class that is used by ICEmu to finf the register function
// NB.  * MUST BE NAMED "RegisterMyHook"
//      * MUST BE global
RegisterHook RegisterMyHook(registerMyCodeHook);
