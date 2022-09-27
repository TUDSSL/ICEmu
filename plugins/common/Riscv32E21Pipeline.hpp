#pragma once
/**
 *  Based on the E2 32-bit RISC core from SiFive
 *  https://sifive.cdn.prismic.io/sifive/6f0f1515-1249-4ea0-a5b2-79d4aaf920ae_e21_core_complex_manual_21G3.pdf - Chapter 3, page 22
 *
 *  3-stage pipeline. Fetch, Execute, Write-back
 *
 *  Fetch unit:
 *      * Fetches are always word-aligned
 *      * 1 cycle penalty for branching to a 32-bit instruction that is not word-aligned
 *          - (so if a 32-bit is not word aligned it needs to do 2 fetches, hence 1 cycle penalty)
 *      * For compressed 16-bit instructions, two instructions can be fetched in one cycle, reducing energy and memory accesses
 *      * All branches are aligned to half-word (16-bit) addresses
 *      * Fetch always accesses memory sequentially
 *      * Conditional branches are **predicted not taken**
 *      * Non-taken Branches incur **no penalty**
 *      * Taken branches and unconditional jumps
 *        incur a one-cycle penalty if the target is naturally aligned.
 *        i.e., all 16-bit instructions and 32-bit instructions whose address is divisible by 4;
 *      * Taken branches and unconditional jumps have a two-cycle penalty if the target is NOT
 *        naturally aligned.
 *
 *  Execution:
 *      * Single-issue in-order pipeline
 *      * Fetch, Execute, Write-back
 *      * Peak execution rate of one instruction per cycle
 *      * Bypass paths are included so that most instructions have a one-cycle result latency
 *      * Exceptions:
 *          - Stall cycles between a load and use is equal to the number of cycles between
 *            the bus request and bus response. In particular, if a load is satisfied the cycle
 *            after it is demanded, then there is one stall cycle between the load and its use.
 *            In this special case, the stall can be obviated by scheduling an independent
 *            instruction between the load and its use.
 *          - Integer divisions have a variable latency of at most 35 cycles.
 *
 *      * In the execute stage, instructions are decoded and checked for exceptions,
 *        and their operands are read from the integer register file.
 *      * Arithmetic instructions compute their results in the execution stage
 *      * Memory-access instructions compute their effective addresses and send their
 *        requests to the bus interface in the execution stage.
 *
 *      Instructions:
 *          Instruction                 | Latency in cycles
 *          LW                          | 2 (assuming cache hit) TIM has 2 cycle access latency
 *          LH, LHU, LB, LBU            | 2 (assuming cache hit) TIM has 2 cycle access latency
 *          CSR Read                    | 1 cycle
 *          MUL, MULH, MULHU, MULHSU    | 1 cycle
 *          DIV, DIVU, REM, REMU        | between 5 and 32 cycles depending on operands
 *                                      |   Latency = 2 + log2(dividend) - log2(divisor)
 *                                      |             + 1 if input is negative + 1 if output is negative
 *
 *  Write-back:
 *      * In the Write-back stage, instructions write their results to the integer register file.
 *      * Instructions that reach the write-back stage but have not yet produced their results
 *        will interlock the pipeline (causing a stall).
 *      * Load and division instructions with result latency grater than one cycle will interlock
 *        the pipeline.
 *
 *  Data Memory System:
 *      * E2 allows for two outstanding memory accesses
 *      * Store instructions incur no stalls if ack-ed by the bus on cycle after they are sent.
 *
 *  Notes:
 *      Seems straightforward. Only loads and divisions seem to be able to stall the pipeline.
 *      However, a store can cause a stall if the memory is not keeping up. This will depend on the memory.
 *      Two can be outstanding (mini cache).
 *
 *      For this approximation we can ignore the memory model, as we will give a model for the cache and
 *      MRAM accesses anyway. If needed, we can build it in later. This is just to give a better idea of
 *      performance instead of using the total instruction count, in addition to Memory access numbers and modeling.
 *
 */
#include <iostream>

#include "capstone/capstone.h"

#include "icemu/emu/types.h"
#include "icemu/emu/Emulator.h"
#include "icemu/hooks/HookCode.h"
#include "icemu/hooks/HookManager.h"
#include "icemu/hooks/RegisterHook.h"

using namespace std;
using namespace icemu;

class RiscvE21Pipeline {
  public:
    typedef std::function<int(cs_insn *insn)> memcost_func_t;

  private:
    Emulator &_emu;
    Emulator &getEmulator() { return _emu; }

    uint64_t TotalCycles = 0;

    bool VerifyJumpDestinationGuess = true;
    uint64_t JumpDestinationGuess = 0;

    bool VerifyNextInstructionGuess = true;
    uint64_t NextInstructionGuess = 0;

    memcost_func_t memoryLoadCost;
    memcost_func_t memoryStoreCost;

    // Default memoryLoadCost
    static int memoryLoadCost_(cs_insn *insn) {
      (void)insn;
      return 2; // Assume a cache hit for now (fastest possible)
    }

    // Default memoryStoreCost
    static int memoryStoreCost_(cs_insn *insn) {
      (void)insn;
      return 1; // Assume enough spacing for now (fastest possible)
    }

    // Map the disassembled capstone register to ICEmu
    address_t getRegisterValue(unsigned int capstone_reg) {
      // Only map general purpose registers for now
      ArchitectureRiscv32::Register reg;
      switch (capstone_reg) {
        case RISCV_REG_X0: reg = ArchitectureRiscv32::REG_X0; break;
        case RISCV_REG_X1: reg = ArchitectureRiscv32::REG_X1; break;
        case RISCV_REG_X2: reg = ArchitectureRiscv32::REG_X2; break;
        case RISCV_REG_X3: reg = ArchitectureRiscv32::REG_X3; break;
        case RISCV_REG_X4: reg = ArchitectureRiscv32::REG_X4; break;
        case RISCV_REG_X5: reg = ArchitectureRiscv32::REG_X5; break;
        case RISCV_REG_X6: reg = ArchitectureRiscv32::REG_X6; break;
        case RISCV_REG_X7: reg = ArchitectureRiscv32::REG_X7; break;
        case RISCV_REG_X8: reg = ArchitectureRiscv32::REG_X8; break;
        case RISCV_REG_X9: reg = ArchitectureRiscv32::REG_X9; break;
        case RISCV_REG_X10: reg = ArchitectureRiscv32::REG_X10; break;
        case RISCV_REG_X11: reg = ArchitectureRiscv32::REG_X11; break;
        case RISCV_REG_X12: reg = ArchitectureRiscv32::REG_X12; break;
        case RISCV_REG_X13: reg = ArchitectureRiscv32::REG_X13; break;
        case RISCV_REG_X14: reg = ArchitectureRiscv32::REG_X14; break;
        case RISCV_REG_X15: reg = ArchitectureRiscv32::REG_X15; break;
        case RISCV_REG_X16: reg = ArchitectureRiscv32::REG_X16; break;
        case RISCV_REG_X17: reg = ArchitectureRiscv32::REG_X17; break;
        case RISCV_REG_X18: reg = ArchitectureRiscv32::REG_X18; break;
        case RISCV_REG_X19: reg = ArchitectureRiscv32::REG_X19; break;
        case RISCV_REG_X20: reg = ArchitectureRiscv32::REG_X20; break;
        case RISCV_REG_X21: reg = ArchitectureRiscv32::REG_X21; break;
        case RISCV_REG_X22: reg = ArchitectureRiscv32::REG_X22; break;
        case RISCV_REG_X23: reg = ArchitectureRiscv32::REG_X23; break;
        case RISCV_REG_X24: reg = ArchitectureRiscv32::REG_X24; break;
        case RISCV_REG_X25: reg = ArchitectureRiscv32::REG_X25; break;
        case RISCV_REG_X26: reg = ArchitectureRiscv32::REG_X26; break;
        case RISCV_REG_X27: reg = ArchitectureRiscv32::REG_X27; break;
        case RISCV_REG_X28: reg = ArchitectureRiscv32::REG_X28; break;
        case RISCV_REG_X29: reg = ArchitectureRiscv32::REG_X29; break;
        case RISCV_REG_X30: reg = ArchitectureRiscv32::REG_X30; break;
        case RISCV_REG_X31: reg = ArchitectureRiscv32::REG_X31; break;
        default:
          assert(false && "CycleCount: Unknown register mapping, fixme");
          break;
      }
      // Return the register value
      return getEmulator().getArchitecture().getRiscv32Architecture().registerGet(reg);
    }

    address_t divisionLatency(int32_t dividend, int32_t divisor) {
      // Latency = 2 + log2(dividend) - log2(divisor) + 1 if input is negative + 1 if output is negative
      //std::cout << "Signed" << " dividend=" << dividend << " divisor=" << divisor << endl;
      auto log2_dividend = (dividend == 0) ? 0 : log2(abs(dividend));
      address_t latency = 2 + (int)log2_dividend + (int)log2(abs(divisor));

      // If input < 0
      if (dividend < 0 || divisor < 0) {
        latency += 1;
      }

      // If output < 0
      if ((dividend/divisor) < 0) {
        latency += 1;
      }

      return latency;
    }

    address_t divisionLatency(uint32_t dividend, uint32_t divisor) {
      // Latency = 2 + log2(dividend) - log2(divisor)
      //std::cout << "Unsigned" << " dividend=" << dividend << " divisor=" << divisor << endl;
      auto log2_dividend = (dividend == 0) ? 0 : log2(dividend);
      address_t latency = 2 + (int)log2_dividend + (int)log2(divisor);
      return latency;
    }

    int divisionCost(cs_insn *insn, bool is_signed) {
      // Get the operants
      auto *cs_riscv = &insn->detail->riscv;
      auto operands = cs_riscv->op_count;

      // Division should always have 3 operands (rd, rs1, rs2)
      assert((operands == 3) && "CycleCount: Unexpected operand count for divisionCost()");

      auto Rd = cs_riscv->operands[0];
      auto Rs1 = cs_riscv->operands[1];
      auto Rs2 = cs_riscv->operands[2];

      // All operands should be registers
      assert((Rd.type == RISCV_OP_REG) && "CycleCount: divisionCost(): Rd is not a register operand");
      assert((Rs1.type == RISCV_OP_REG) && "CycleCount: divisionCost(): Rd is not a register operand");
      assert((Rs2.type == RISCV_OP_REG) && "CycleCount: divisionCost(): Rd is not a register operand");

      //std::cout << "Rd: " << Rd.reg << " = " << getRegisterValue(Rd.reg) << endl;
      //std::cout << "Rs1: " << Rs1.reg << " = " << getRegisterValue(Rs1.reg) << endl;
      //std::cout << "Rs2: " << Rs2.reg << " = " << getRegisterValue(Rs2.reg) << endl;

      // Rs1/Rs2
      uint64_t dividend = getRegisterValue(Rs1.reg);
      uint64_t divisor = getRegisterValue(Rs2.reg);

      address_t latency;

      if (is_signed) {
        latency = divisionLatency((int32_t)dividend, (int32_t)divisor);
      } else {
        latency = divisionLatency((uint32_t)dividend, (uint32_t)divisor);
      }

      if (latency > 70) {
        cerr << "CycleCount: latency estimate > 70, error in computation, latency=" << latency << endl;
        assert(false);
      }

      if (latency > 35) {
        latency = 35;
      }

      return 1;
    }

    // Jump cost: 
    // Non-taken Branches incur **no penalty**
    // A one-cycle penalty if the *target* is naturally aligned.
    // i.e., all 16-bit instructions and 32-bit instructions whose address is divisible by 4;
    // A two-cycle penalty if the target is NOT naturally aligned
    int jumpPenalty(address_t jump_destination, bool takes_branch) {
      if (takes_branch == false) {
        return 0;
      }

      if (jump_destination%4 == 0) {
        // Naturally aligned
        return 1; // One cycle penalty
      } else {
        // NOT naturally aligned
        return 2; // Two cycle penalty
      }
    }

    // Unconditional jumps always have the cost of filling the pipeline
    int unconditionalJumpCost(cs_insn *insn, riscv_insn rvinsn) {
      auto *cs_riscv = &insn->detail->riscv;
      address_t jump_destination = 0;

      auto arch = getEmulator().getArchitecture().getRiscv32Architecture();
      auto PC = arch.registerGet(ArchitectureRiscv32::REG_PC);

      auto op_count = cs_riscv->op_count;
      auto *operands = cs_riscv->operands;

      switch (rvinsn) {
        case RISCV_INS_JAL:
          {
            cs_riscv_op OpImm;
            if (op_count == 1) {
              // J pseudo
              OpImm = operands[0];
            } else if (op_count == 2) {
              // JAL
              OpImm = operands[1];
            } else {
              assert(false && "Unhandled JAL jump operands version");
            }
            assert(OpImm.type == RISCV_OP_IMM);
            jump_destination = PC + OpImm.imm*2;
          }
          break;

        case RISCV_INS_JALR:
          {
            if (op_count == 1) {
              auto OpRs1 = operands[0];
              assert(OpRs1.type == RISCV_OP_REG);
              jump_destination = OpRs1.reg & ~1; // Clear the LSB
            } else if (op_count == 3) {
              auto OpRs1 = operands[1];
              auto OpImm = operands[2];
              assert(OpRs1.type == RISCV_OP_REG);
              assert(OpImm.type == RISCV_OP_IMM);
              jump_destination = (OpRs1.reg + OpImm.imm) & ~1; // Clear the LSB
            } else {
              assert(false && "Unhandled JALR jump operands version");
            }
          }
          break;

        case RISCV_INS_C_J:
          {
            assert(op_count == 1);
            auto Op0 = operands[0];
            assert(Op0.type == RISCV_OP_IMM);
            jump_destination = PC + Op0.imm;
          }
          break;

        case RISCV_INS_C_JAL:
          {
            assert(op_count == 1);
            auto Op0 = operands[0];
            assert(Op0.type == RISCV_OP_IMM);
            jump_destination = PC + Op0.imm;
          }
          break;

        case RISCV_INS_C_JR:
          {
            assert(op_count == 1);
            auto OpRs1 = operands[0];
            assert(OpRs1.type == RISCV_OP_REG);
            jump_destination = OpRs1.reg;
          }
          break;

        case RISCV_INS_C_JALR:
          {
            assert(op_count == 1);
            auto OpRs1 = operands[0];
            assert(OpRs1.type == RISCV_OP_REG);
            jump_destination = OpRs1.reg;
          }
          break;

        default:
          assert(false && "Switch-Case mismatch in unconditionalJumpCost");
      }
      
      // Set the jump destination guess to verify the jump in the next cycle
      JumpDestinationGuess = jump_destination;

      // Compute the jump cost
      int jump_cost = 1 + jumpPenalty(jump_destination, true);
      return jump_cost;
    }

    // Conditional jumps only have the cost of filling the pipeline IF the
    // condition holds (i.e, if they jump)
    int conditionalJumpCost(cs_insn *insn, riscv_insn rvinsn) {
      auto *cs_riscv = &insn->detail->riscv;
      address_t jump_destination = 0;
      bool takes_branch = false;

      auto arch = getEmulator().getArchitecture().getRiscv32Architecture();
      auto PC = arch.registerGet(ArchitectureRiscv32::REG_PC);

      auto op_count = cs_riscv->op_count;
      auto *operands = cs_riscv->operands;

      switch (rvinsn) {
        // Conditional Branch
        case RISCV_INS_BEQ:
          {
            if (op_count == 2) {
              // pseudo BEQZ
              auto OpRs1 = operands[0];
              auto OpImm = operands[1];
              assert(OpRs1.type == RISCV_OP_REG);
              assert(OpImm.type == RISCV_OP_IMM);
              uint32_t Rs1 = getRegisterValue(OpRs1.reg);
              if (Rs1 == 0) takes_branch = true;
              jump_destination = PC + OpImm.imm*2;
            } else if (op_count == 3) {
              auto OpRs1 = operands[0];
              auto OpRs2 = operands[1];
              auto OpImm = operands[2];
              assert(OpRs1.type == RISCV_OP_REG);
              assert(OpRs2.type == RISCV_OP_REG);
              assert(OpImm.type == RISCV_OP_IMM);
              uint32_t Rs1 = getRegisterValue(OpRs1.reg);
              uint32_t Rs2 = getRegisterValue(OpRs2.reg);
              if (Rs1 == Rs2) takes_branch = true;
              jump_destination = PC + OpImm.imm*2;
            } else {
              assert(false && "CycleCount: BEQ expected 2 or 3 arguments");
            }
          }
          break;
        case RISCV_INS_BNE:
          {
            if (op_count == 2) {
              // pseudo BNEZ Rs, offset
              auto OpRs1 = operands[0];
              auto OpImm = operands[1];
              assert(OpRs1.type == RISCV_OP_REG);
              assert(OpImm.type == RISCV_OP_IMM);
              auto Rs1 = getRegisterValue(OpRs1.reg);
              if (Rs1 != 0) takes_branch = true;
              jump_destination = PC + OpImm.imm*2;
            } else if (op_count == 3) {
              auto OpRs1 = operands[0];
              auto OpRs2 = operands[1];
              auto OpImm = operands[2];
              assert(OpRs1.type == RISCV_OP_REG);
              assert(OpRs2.type == RISCV_OP_REG);
              assert(OpImm.type == RISCV_OP_IMM);
              auto Rs1 = getRegisterValue(OpRs1.reg);
              auto Rs2 = getRegisterValue(OpRs2.reg);
              if (Rs1 != Rs2) takes_branch = true;
              jump_destination = PC + OpImm.imm*2;
            } else {
              assert(false && "CycleCount: BNE expected 2 or 3 arguments");
            }
          }
          break;
        case RISCV_INS_BLT:
          {
            if (op_count == 2) {
              // pseudo bgtz
              auto OpRs1 = operands[0];
              auto OpImm = operands[1];
              assert(OpRs1.type == RISCV_OP_REG);
              assert(OpImm.type == RISCV_OP_IMM);
              int32_t Rs1 = getRegisterValue(OpRs1.reg);
              if (Rs1 > 0) takes_branch = true;
              jump_destination = PC + OpImm.imm*2;
            } else if (op_count == 3) {
              auto OpRs1 = operands[0];
              auto OpRs2 = operands[1];
              auto OpImm = operands[2];
              assert(OpRs1.type == RISCV_OP_REG);
              assert(OpRs2.type == RISCV_OP_REG);
              assert(OpImm.type == RISCV_OP_IMM);
              int32_t Rs1 = getRegisterValue(OpRs1.reg);
              int32_t Rs2 = getRegisterValue(OpRs2.reg);
              if (Rs1 < Rs2) takes_branch = true;
              jump_destination = PC + OpImm.imm*2;
            } else {
              assert(false && "CycleCount: BLT expected 2 or 3 arguments");
            }
          }
          break;
        case RISCV_INS_BGE:
          {
            if (op_count == 2) {
              // pseudo BLEZ
              auto OpRs1 = operands[0];
              auto OpImm = operands[1];
              assert(OpRs1.type == RISCV_OP_REG);
              assert(OpImm.type == RISCV_OP_IMM);
              int32_t Rs1 = getRegisterValue(OpRs1.reg);
              if (Rs1 <= 0) takes_branch = true;
              jump_destination = PC + OpImm.imm*2;
            } else if (op_count == 3) {
              auto OpRs1 = operands[0];
              auto OpRs2 = operands[1];
              auto OpImm = operands[2];
              assert(OpRs1.type == RISCV_OP_REG);
              assert(OpRs2.type == RISCV_OP_REG);
              assert(OpImm.type == RISCV_OP_IMM);
              int32_t Rs1 = getRegisterValue(OpRs1.reg);
              int32_t Rs2 = getRegisterValue(OpRs2.reg);
              if (Rs1 >= Rs2) takes_branch = true;
              jump_destination = PC + OpImm.imm*2;
            } else {
              assert(false && "CycleCount: BGE expected 2 or 3 arguments");
            }
          }
          break;
        case RISCV_INS_BLTU:
          {
            assert(op_count == 3);
            auto OpRs1 = operands[0];
            auto OpRs2 = operands[1];
            auto OpImm = operands[2];
            assert(OpRs1.type == RISCV_OP_REG);
            assert(OpRs2.type == RISCV_OP_REG);
            assert(OpImm.type == RISCV_OP_IMM);
            uint32_t Rs1 = getRegisterValue(OpRs1.reg);
            uint32_t Rs2 = getRegisterValue(OpRs2.reg);
            if (Rs1 < Rs2) takes_branch = true;
            jump_destination = PC + OpImm.imm*2;
          }
          break;
        case RISCV_INS_BGEU:
          {
            assert(op_count == 3);
            auto OpRs1 = operands[0];
            auto OpRs2 = operands[1];
            auto OpImm = operands[2];
            assert(OpRs1.type == RISCV_OP_REG);
            assert(OpRs2.type == RISCV_OP_REG);
            assert(OpImm.type == RISCV_OP_IMM);
            uint32_t Rs1 = getRegisterValue(OpRs1.reg);
            uint32_t Rs2 = getRegisterValue(OpRs2.reg);
            if (Rs1 >= Rs2) takes_branch = true;
            jump_destination = PC + OpImm.imm*2;
          }
          break;
        case RISCV_INS_C_BEQZ:
          {
            assert(op_count == 2);
            auto OpRs1 = operands[0];
            auto OpImm = operands[1];
            assert(OpRs1.type == RISCV_OP_REG);
            assert(OpImm.type == RISCV_OP_IMM);
            auto Rs1 = getRegisterValue(OpRs1.reg);
            if (Rs1 == 0) takes_branch = true;
            jump_destination = PC + OpImm.imm;
          }
          break;
        case RISCV_INS_C_BNEZ:
          {
            assert(op_count == 2);
            auto OpRs1 = operands[0];
            auto OpImm = operands[1];
            assert(OpRs1.type == RISCV_OP_REG);
            assert(OpImm.type == RISCV_OP_IMM);
            auto Rs1 = getRegisterValue(OpRs1.reg);
            if (Rs1 != 0) takes_branch = true;
            jump_destination = PC + OpImm.imm;
          }
          break;

        default:
          assert(false && "Switch-Case mismatch in unconditionalJumpCost");
      }

      // Set the jump destination guess to verify the jump in the next cycle
      if (takes_branch) {
        JumpDestinationGuess = jump_destination;
      } else {
        JumpDestinationGuess = 0; // No jump
      }

      // Compute the jump cost
      int jump_cost = 1 + jumpPenalty(jump_destination, true);
      return jump_cost;
    }

    /*
     * We don't actually emulate the pipeline, but model the cost.
     * We try to see if we will incur a stall or not, otherwise the cost is just 1
     */
    int instructionCost(cs_insn *insn) {
      riscv_insn rvinsn = (riscv_insn)insn->id;
      int this_cost = 0;

      // We want to catch the "normal" and "compressed" instructions
      // Compressed instructions can actually reduce program memory fetches
      // But we ignore that memory for now
      switch (rvinsn) {
        // Memory load
        case RISCV_INS_LW:
        case RISCV_INS_LH:
        case RISCV_INS_LHU:
        case RISCV_INS_LB:
        case RISCV_INS_LBU:
        case RISCV_INS_C_LW:
        case RISCV_INS_C_LWSP:
          this_cost = memoryLoadCost(insn);
          break;
        
        // Memory store
        case RISCV_INS_SW:
        case RISCV_INS_SH:
        case RISCV_INS_SB:
        case RISCV_INS_C_SW:
        case RISCV_INS_C_SWSP:
          this_cost = memoryStoreCost(insn);
          break;

        // Division
        case RISCV_INS_DIV:
        case RISCV_INS_REM:
          this_cost = divisionCost(insn, true);
          break;
        case RISCV_INS_DIVU:
        case RISCV_INS_REMU:
          this_cost = divisionCost(insn, false);
          break;
        // These are not 32-bit, why are they in the SiFive E21 manual?
        // I guess we can handle them, but I kinda want to know if they pop up
        // So place an assert for now
        case RISCV_INS_REMW:
        case RISCV_INS_REMUW:
          assert(false && "CycleCount: Not handled REM instruction, manual is inconsistent");
          break;

        // Unconditional Jumps
        case RISCV_INS_JAL:
        case RISCV_INS_JALR:
        case RISCV_INS_C_J:
        case RISCV_INS_C_JAL:
        case RISCV_INS_C_JR:
        case RISCV_INS_C_JALR:
          this_cost = unconditionalJumpCost(insn, rvinsn);
          break;
        // Conditional Branch
        case RISCV_INS_BEQ:
        case RISCV_INS_BNE:
        case RISCV_INS_BLT:
        case RISCV_INS_BGE:
        case RISCV_INS_BLTU:
        case RISCV_INS_BGEU:
        case RISCV_INS_C_BEQZ:
        case RISCV_INS_C_BNEZ:
          this_cost = conditionalJumpCost(insn, rvinsn);
          break;

        default:
          this_cost = 1;
      };

      //std::cout << "Cost of this instruction was: " << this_cost << endl;
      return this_cost;
    }

    void add(cs_insn *insn) {
      TotalCycles += instructionCost(insn);
    }

    void verifyJump(address_t address) {

      if (VerifyNextInstructionGuess == true) {
        if ( NextInstructionGuess != 0
            && JumpDestinationGuess == 0 
            && NextInstructionGuess != address) {
          // No jump instruction handled but we jumped
          cerr << "CycleCounter: missed a jump instruction, next expected: 0x" << hex
               << NextInstructionGuess << " actual address is: 0x" << address << dec << endl;
          getEmulator().stop("CycleCounter: Jump prediction error");
          return;
        } else {
          JumpDestinationGuess = 0;
        }
      }

      if (VerifyJumpDestinationGuess == true) {
        // Verify the last jump instruction (if any)
        if (JumpDestinationGuess != 0 && JumpDestinationGuess != address) {
          cerr << "CycleCounter: miscalculated a jump instruction, guessed: 0x" << hex
               << JumpDestinationGuess << " actual address is: 0x" << address << dec << endl;
          getEmulator().stop("CycleCounter: Jump prediction error");
          return;
        } else {
          JumpDestinationGuess = 0;
        }
      }
    }

  public:
    RiscvE21Pipeline(Emulator &emu) : _emu(emu) {
      memoryLoadCost = memoryLoadCost_;
      memoryStoreCost = memoryStoreCost_;
    }

    RiscvE21Pipeline(Emulator &emu,
        memcost_func_t *memoryLoadCostFunc, 
        memcost_func_t *memoryStoreCostFunc) : _emu(emu) {
      if (memoryLoadCostFunc == nullptr) {
        memoryLoadCost = memoryLoadCost_;
      } else {
        memoryLoadCost = *memoryLoadCostFunc;
      }

      if (memoryStoreCostFunc == nullptr) {
        memoryStoreCost = *memoryStoreCost_;
      } else {
        memoryStoreCost = *memoryStoreCostFunc;
      }
    }

    uint64_t getTotalCycles() { return TotalCycles; }

    void addToCycles(int d) {
      TotalCycles += d;
    }

    void setVerifyJumpDestinationGuess(bool flag) {
      VerifyJumpDestinationGuess = flag;
    }

    void setVerifyNextInstructionGuess(bool flag) {
      VerifyNextInstructionGuess = flag;
    }

    void add(address_t address, address_t size) {
      // Verify jumps
      verifyJump(address);

      // Process the instruction
      uint8_t instruction[size];

      bool ok = getEmulator().readMemory(address, (char *)instruction, size);
      if (!ok) {
        std::cerr << "CycleCounter: failed to read memory for instruction at address " << address << std::endl;
        assert(false);
      }

      cs_insn *insn = NULL;
      size_t cnt = cs_disasm(*getEmulator().getCapstoneEngine(), instruction, size, address, 1, &insn);
      if (cnt == 0) {
        std::cerr << "CycleCounter: failed to disassemble instruction at address " << address << std::endl;
        assert(false);
      }

      // Add the actual instruction
      add(insn);

      // Free the memory
      cs_free(insn, cnt);

      // The next instruction should be PC + size, otherwise there was a Jump/Branch instruction
      // which should be caught by JumpDestinationGuess. So add NextInstructionGuess to verify
      // that we handle all the jump instructions. (This will go wring if we insert interrupts,
      // this should only be here for debugging)
      NextInstructionGuess = address + size;
    }

};
