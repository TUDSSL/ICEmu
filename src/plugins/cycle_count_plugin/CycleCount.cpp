/**
 *  ICEmu loadable plugin (library)
 *
 * An example ICEmu plugin that is dynamically loaded.
 * This example prints the address of each instruction that is executed.
 *
 * Should be compiled as a shared library, i.e. using `-shared -fPIC`
 */
#include <iostream>

#include "capstone/capstone.h"

#include "icemu/emu/Emulator.h"
#include "icemu/hooks/HookCode.h"
#include "icemu/hooks/HookManager.h"
#include "icemu/hooks/RegisterHook.h"

using namespace std;
using namespace icemu;

// A 3-stage pipeline for arm
class Pipeline {
 private:

  bool pipeline_cost = false;
  armaddr_t addr_prev_instruction = 0;

 public:
  uint64_t cycle_count = 0;

  // Add a capstone instruction to the pipeline
  void add(cs_insn *insn) {

    // Indexes into the arm_insn table in capstone
    arm_insn instruction = (arm_insn)insn->id;

    // Get the operands (if it touches the PC we might need to refil the
    // pipeline)
    auto *cs_arm = &insn->detail->arm;
    int operand_count = cs_arm->op_count;
    auto *operands = cs_arm->operands;

    int P = 3; // pipeline refill cost
    int instruction_cost = 1;

    // Approximate
    // Info from: https://developer.arm.com/documentation/ddi0439/b/Programmers-Model/Instruction-set-summary/Cortex-M4-instructions
    switch (instruction) {
      case ARM_INS_MOV:
      case ARM_INS_MOVT:
      case ARM_INS_MOVW:
      case ARM_INS_ADD:
      case ARM_INS_ADC:
      case ARM_INS_ADR:
      case ARM_INS_SUB:
      case ARM_INS_SBC:
      case ARM_INS_RSB:
      case ARM_INS_SUBW:
        if ((operand_count > 0) && (operands[0].reg == ARM_REG_PC)) {
          instruction_cost = 1 + P;
        }
        break;

      case ARM_INS_MLA:
      case ARM_INS_MLS:
        instruction_cost = 2;
        break;

      // For DIV instructions the cost can be between 2 and 12 depending on the
      // number of leading zeros in the operands.
      // TODO: Find out how the cost is computed
      case ARM_INS_SDIV:
      case ARM_INS_UDIV:
        instruction_cost = 7; // magic number between 2 and 12 included
        break;

      // "Neighboring load and store single instructions can pipeline their
      // address and data phases. This enables these instructions to complete in
      // a single execution cycle."
      // TODO: There is no info on when this happens
      case ARM_INS_LDR:
      case ARM_INS_LDRH:
      case ARM_INS_LDRB:
      case ARM_INS_LDRSH:
      case ARM_INS_LDRSB:
      case ARM_INS_LDRT:
      case ARM_INS_LDRHT:
      case ARM_INS_LDRBT:
      case ARM_INS_LDRSHT:
      case ARM_INS_LDRSBT:
        if ((operand_count > 0) && (operands[0].reg == ARM_REG_PC)) {
          instruction_cost = 2 + P;
        }
        break;

      // Double word loads
      case ARM_INS_LDM:
        instruction_cost = 1 + operand_count;
        {
          for (int i=0; i<operand_count; i++) {
            if (operands[i].reg == ARM_REG_PC) {
              instruction_cost += P;
              break;
            }
          }
        }
        cout << "Using LDM instruction with " << operand_count << " operands" << endl;
        break;

      // Stores
      case ARM_INS_STORE


      default:
        // already set the default
        break;
    }
  }

};

class CycleCount : public HookCode {
 private:
  std::string printLeader() {
    return "[instr]";
  }

  Pipeline pipeline;

 public:
  // Always execute
  CycleCount(Emulator &emu) : HookCode(emu, "display_instructions") {
  }

  ~CycleCount() {
  }

  void displayInstruction(armaddr_t address, armaddr_t size) {
    bool ok;
    uint8_t instruction[size];

    ok = getEmulator().readMemory(address, (char *)instruction, size);
    if (!ok) {
      cerr << printLeader() << " failed to read memory for instruction at address " << address << endl;
      return;
    }
    cs_insn *insn;
    size_t cnt = cs_disasm(*getEmulator().getCapstoneEngine(), instruction, size, address, 0, &insn);
    if (cnt == 0) {
      cerr << printLeader() << " failed to disasemble instruction at address " << address << endl;
      return;
    }

    // Display the actual instruction
    for (size_t i=0; i<cnt; i++) {
      cout << printLeader() << " ";
      printf("0x%08x: %s  %s", (armaddr_t)insn[i].address, insn[i].mnemonic, insn[i].op_str);
      cout << endl;
    }

    pipeline.add(insn);
    cs_free(insn, cnt);
  }

  // Hook run
  void run(hook_arg_t *arg) {
    displayInstruction(arg->address, arg->size);
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
