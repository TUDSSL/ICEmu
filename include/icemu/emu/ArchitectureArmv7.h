#pragma once

#include <cstdint>
#include <iostream>
#include <assert.h>

#include <unicorn/unicorn.h>

#include "Arch.h"

namespace icemu {

class ArchitectureArmv7 {
 private:
   uc_engine *uc_ = nullptr;

 public:
  typedef uint32_t armv7_addr_t;

  void init(uc_engine *uc) {
    uc_ = uc;
  }

  inline Arch getArch() { return EMU_ARCH_ARMV7; }
  inline address_t getAddressSize() { return sizeof(armv7_addr_t); };

  enum Register {
    REG_R0 = UC_ARM_REG_R0,
    REG_R1 = UC_ARM_REG_R1,
    REG_R2 = UC_ARM_REG_R2,
    REG_R3 = UC_ARM_REG_R3,
    REG_R4 = UC_ARM_REG_R4,
    REG_R5 = UC_ARM_REG_R5,
    REG_R6 = UC_ARM_REG_R6,
    REG_R7 = UC_ARM_REG_R7,
    REG_R8 = UC_ARM_REG_R8,
    REG_R9 = UC_ARM_REG_R9,
    REG_R10 = UC_ARM_REG_R10,
    REG_R11 = UC_ARM_REG_R11,
    REG_R12 = UC_ARM_REG_R12,
    REG_R13 = UC_ARM_REG_R13,
    REG_R14 = UC_ARM_REG_R14,
    REG_R15 = UC_ARM_REG_R15,
    REG_SP = UC_ARM_REG_SP,
    REG_PC = UC_ARM_REG_PC,
    REG_LR = UC_ARM_REG_LR,
    REG_APSR = UC_ARM_REG_APSR,

    REG_RETURN = UC_ARM_REG_R0,
  };

  // Register manipulation
  armv7_addr_t registerGet(Register reg) {
    armv7_addr_t value;
    uc_reg_read(uc_, reg, &value);
    return value;
  }

  void registerSet(Register reg, armv7_addr_t value) {
    uc_reg_write(uc_, reg, &value);
  }

  // Function manipulation
  void functionSkip() {
    registerSet(REG_PC, registerGet(REG_LR));
  }

  void functionSetReturn(uint32_t value) {
    registerSet(REG_R0, value);
  }

  // 64-bit version
  void functionSetReturn(uint64_t value) {
    registerSet(REG_R0, value & ((1UL<<32)-1));
    registerSet(REG_R1, value >> 32);
  }

  armv7_addr_t functionGetArgument(std::size_t n) {
    // Assume each argument is in a different register
    armv7_addr_t value;

    // Might change that the registers are actually one appart in unicorn,
    // this is a safe way (but looks silly)
    switch (n) {
      case 0:
        value = registerGet(REG_R0);
        break;
      case 1:
        value = registerGet(REG_R1);
        break;
      case 2:
        value = registerGet(REG_R2);
        break;
      case 3:
        value = registerGet(REG_R3);
        break;
      default:
        value = 0;
        std::cerr << "More than 4 funciton arguments are not implemented" << std::endl;
        break;
    }
    return value;
  }
};
}
