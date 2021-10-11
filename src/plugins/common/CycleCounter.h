#ifndef ICEMU_PLUGINS_CYCLE_COUNT_H_
#define ICEMU_PLUGINS_CYCLE_COUNT_H_

#include <icemu/emu/types.h>
#include <iostream>
#include <vector>

#include "capstone/capstone.h"
#include "icemu/emu/Emulator.h"

class Pipeline {
 private:

  uint64_t expected_next_instruction_addr = 0;

  // Store the IMM operands of the last instruction
  std::vector<icemu::armaddr_t> last_instr_immediates;

  int cost(arm_insn instruction, int operand_count) {
    int instruction_cost = 1;

    // Approximate
    // Info from: https://developer.arm.com/documentation/ddi0439/b/Programmers-Model/Instruction-set-summary/Cortex-M4-instructions
    switch (instruction) {
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
        instruction_cost = 2;
        break;

      // Double word loads
      case ARM_INS_LDRD:
        instruction_cost = 1+2; // 1+N N=2
        break;

      case ARM_INS_LDM:
      case ARM_INS_LDMDA:
      case ARM_INS_LDMDB:
      case ARM_INS_LDMIB:
        instruction_cost = 1 + (operand_count-1); // cost is 1+N where N is the register list (number of op -1)
        break;

      // Stores
      case ARM_INS_STR:
      case ARM_INS_STRBT:
      case ARM_INS_STRB:
      case ARM_INS_STRH:
      case ARM_INS_STRHT:
      case ARM_INS_STRT:
        instruction_cost = 2; // just as load, it can be compacted to 1 TODO
        break;

      case ARM_INS_STRD:
        instruction_cost = 1+2; // 1+N N=2
        break;

      case ARM_INS_STMDA:
      case ARM_INS_STMDB:
      case ARM_INS_STM:
      case ARM_INS_STMIB:
        instruction_cost = 1 + (operand_count-1); // cost is 1+N where N is the register list (number of op -1)
        break;

      case ARM_INS_PUSH:
      case ARM_INS_POP:
        instruction_cost = 1 + operand_count;
        break;

      case ARM_INS_LDREX:
      case ARM_INS_LDREXH:
      case ARM_INS_LDREXB:
      case ARM_INS_STREX:
      case ARM_INS_STREXH:
      case ARM_INS_STREXB:
        instruction_cost = 2;
        break;

      case ARM_INS_TBB:
      case ARM_INS_TBH:
        instruction_cost = 2;
        break;

      case ARM_INS_ISB:
        instruction_cost = 1 + 3;
        break;

      case ARM_INS_DMB:
      case ARM_INS_DSB:
        instruction_cost = 1; // this is implementation specific
        break;

      default:
        // already set the default
        break;
    }
    return instruction_cost;
  }

  // Returns the pipeline cost of goind from the previous instruction to this
  // one. So we estimate it after the fact.
  int pipleline_cost(cs_insn *insn) {
    // If the previous address is futher away than one instruction we jumped.
    // SO that means the pipeline was reset (non-taken branch is predicted and
    // does not requre a refill of the pipeline).
    // Branch prediction is magic, but we going to assume this is correct enough:
    // https://stackoverflow.com/questions/28760617/pipeline-refill-cycles-for-instructions-in-arm
    //
    // So if the target (this_address, because we are doing this after the fact)
    // * is 32-bit halfword-aligned it's 3 cycles
    // * is 32-bit and word-alighned it's 2 cycles
    // * is 16-bit it's 2 cycles
    // * is predicted it's 1 cycle: the branch causing instruction was
    //    unconditional AND had the immediate value of the current address.
    int P = 0;

    uint64_t this_address = insn->address;
    // Check if we jumped
    if (this_address != expected_next_instruction_addr) {
      // if thhis address
      bool static_jump = false;
      for (const auto imm : last_instr_immediates) {
        if (this_address == imm) {
          // We jumped to a constant immediate, so we assume that ARM can
          // predict the jump. i.e., P=1
          P = 1;
          static_jump = true;
          //cout << "Predicted the jump!" << endl;
          break;
        }
      }

      if (!static_jump) {
        if (insn->size == 4) {
          if (!(this_address & 0b11)) {
            P = 2;  // word aligned
          } else {
            P = 3;  // not word aligned
          }
        } else {
          // 16-bit instruction
          P = 2;
        }
      }
    }
    return P;
  }

 public:
  uint64_t cycle_count = 0;

  // Add a capstone instruction to the pipeline
  int add(cs_insn *insn) {

    // Indexes into the arm_insn table in capstone
    arm_insn instruction = (arm_insn)insn->id;

    // Get the operands (if it touches the PC we might need to refil the
    // pipeline)
    auto *cs_arm = &insn->detail->arm;
    int operand_count = cs_arm->op_count;
    uint64_t this_address = insn->address;

    int cycles = cost(instruction, operand_count);
    int P = pipleline_cost(insn);

    cycle_count += cycles + P;

    // Prepare for the next instruction
    expected_next_instruction_addr = this_address + insn->size;

    last_instr_immediates.clear();
    // The jump can be predicted IF the jump is unconditional
    // AND if the destination is an immediate.
    // Note: this is a guess, ARM never revealed how it does branch prediction
    if (cs_arm->cc == ARM_CC_AL) {
      auto *operands = cs_arm->operands;
      for (int i=0; i<operand_count; i++) {
        auto *op = &operands[i];
        if (op->type == ARM_OP_IMM) {
          last_instr_immediates.push_back((icemu::armaddr_t)op->imm);
        }
      }
    }
    return cycles + P;
  }
};

class CycleCounter {
  icemu::Emulator &emu;
  Pipeline pipeline;

 public:
  CycleCounter(icemu::Emulator &emu) : emu(emu) {}

  uint64_t cycleCount() {
    return pipeline.cycle_count;
  }

  uint16_t add(icemu::armaddr_t address, icemu::armaddr_t size) {
    bool ok;
    uint8_t instruction[size];

    ok = emu.readMemory(address, (char *)instruction, size);
    if (!ok) {
      std::cerr << "CycleCounter: failed to read memory for instruction at address " << address << std::endl;
      return 0;
    }
    cs_insn *insn;
    size_t cnt = cs_disasm(*emu.getCapstoneEngine(), instruction, size, address, 0, &insn);
    if (cnt == 0) {
      std::cerr << "CycleCounter: failed to disasemble instruction at address " << address << std::endl;
      return 0 ;
    }

    auto cost = pipeline.add(insn);

    cs_free(insn, cnt);

    return cost;
  }

};


#endif /* ICEMU_PLUGINS_CYCLE_COUNT_H_ */
