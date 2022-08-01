/**
 *  ICEmu loadable plugin (library)
 *
 */
#include <iostream>

#include "capstone/capstone.h"

#include "icemu/emu/types.h"
#include "icemu/emu/Emulator.h"
#include "icemu/hooks/HookCode.h"
#include "icemu/hooks/HookManager.h"
#include "icemu/hooks/RegisterHook.h"

#include "Riscv32E21Pipeline.hpp"
#include "PluginArgumentParsing.h"

using namespace std;
using namespace icemu;

class Riscv32CycleCount : public HookCode {
 private:
  std::string printLeader() {
    return "[riscv_cycle_count]";
  }

  RiscvE21Pipeline Pipeline;

 public:
  // Always execute
  Riscv32CycleCount(Emulator &emu) : HookCode(emu, "riscv32_cycle_count"), Pipeline(emu) {
    auto verify_jump_arg = PluginArgumentParsing::GetArguments(emu, "riscv32-cycle-count-fno-verify-jump");
    if (verify_jump_arg.size()) {
      cout << printLeader() << " Disabling VerifyJumpDestinationGuess" << endl;
      Pipeline.setVerifyJumpDestinationGuess(false);
    }

    auto verify_next_instr_arg = PluginArgumentParsing::GetArguments(emu, "riscv32-cycle-count-fno-verify-next-instr");
    if (verify_next_instr_arg.size()) {
      cout << printLeader() << " Disabling setVerifyNextInstructionGuess" << endl;
      Pipeline.setVerifyNextInstructionGuess(false);
    }
  }

  ~Riscv32CycleCount() {
    cout << printLeader() << " Total estimated cycle count: " << Pipeline.getTotalCycles() << " cycles" << endl;
  }

  // Hook run
  void run(hook_arg_t *arg) {
    Pipeline.add(arg->address, arg->size);
  }
};

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  HM.add(new Riscv32CycleCount(emu));
}

// Class that is used by ICEmu to finf the register function
// NB.  * MUST BE NAMED "RegisterMyHook"
//      * MUST BE global
RegisterHook RegisterMyHook(registerMyCodeHook);
