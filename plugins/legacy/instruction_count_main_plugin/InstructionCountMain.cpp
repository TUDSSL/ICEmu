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

static bool in_main = false;

class HookMain : public HookFunction {

 public:
  // Always execute
  HookMain(Emulator &emu, string fname) : HookFunction(emu, fname) {}

  ~HookMain() {
  }

  // Hook run
  void run(hook_arg_t *arg) {
    (void)arg;
    in_main = true;
  }
};

class InstructionCountMain : public HookCode {
 private:
  uint64_t icnt;

 public:
  // Always execute
  InstructionCountMain(Emulator &emu) : HookCode(emu, "icnt-main") {}

  ~InstructionCountMain() {
    std::cout << "Main ran for: " << icnt << " instructions" << std::endl;
  }

  // Hook run
  void run(hook_arg_t *arg) {
    (void)arg;
    if (in_main) ++icnt;
  }
};

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  auto hicnt = new InstructionCountMain(emu);
  auto hf = new HookMain(emu, "main");
  if (hf->getStatus() == Hook::STATUS_ERROR) {
    delete hf;
    delete hicnt;
    return;
  }

  HM.add(hicnt);
  HM.add(hf);
}

// Class that is used by ICEmu to finf the register function
// NB.  * MUST BE NAMED "RegisterMyHook"
//      * MUST BE global
RegisterHook RegisterMyHook(registerMyCodeHook);
