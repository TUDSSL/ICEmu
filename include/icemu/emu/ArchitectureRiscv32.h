#pragma once

#include <cstdint>
#include <iostream>
#include <assert.h>

#include <unicorn/unicorn.h>

#include "Arch.h"

namespace icemu {

class ArchitectureRiscv32 {
 private:
   uc_engine *uc_ = nullptr;

 public:
  typedef uint32_t riscv_addr_t;

  void init(uc_engine *uc) {
    uc_ = uc;
  }

  inline Arch getArch() { return EMU_ARCH_RISCV32; }
  inline address_t getAddressSize() { return sizeof(riscv_addr_t); };

  enum Register {
    REG_X0  = UC_RISCV_REG_X0,
    REG_X1  = UC_RISCV_REG_X1,
    REG_X2  = UC_RISCV_REG_X2,
    REG_X3  = UC_RISCV_REG_X3,
    REG_X4  = UC_RISCV_REG_X4,
    REG_X5  = UC_RISCV_REG_X5,
    REG_X6  = UC_RISCV_REG_X6,
    REG_X7  = UC_RISCV_REG_X7,
    REG_X8  = UC_RISCV_REG_X8,
    REG_X9  = UC_RISCV_REG_X9,
    REG_X10 = UC_RISCV_REG_X10,
    REG_X11 = UC_RISCV_REG_X11,
    REG_X12 = UC_RISCV_REG_X12,
    REG_X13 = UC_RISCV_REG_X13,
    REG_X14 = UC_RISCV_REG_X14,
    REG_X15 = UC_RISCV_REG_X15,
    REG_X16 = UC_RISCV_REG_X16,
    REG_X17 = UC_RISCV_REG_X17,
    REG_X18 = UC_RISCV_REG_X18,
    REG_X19 = UC_RISCV_REG_X19,
    REG_X20 = UC_RISCV_REG_X20,
    REG_X21 = UC_RISCV_REG_X21,
    REG_X22 = UC_RISCV_REG_X22,
    REG_X23 = UC_RISCV_REG_X23,
    REG_X24 = UC_RISCV_REG_X24,
    REG_X25 = UC_RISCV_REG_X25,
    REG_X26 = UC_RISCV_REG_X26,
    REG_X27 = UC_RISCV_REG_X27,
    REG_X28 = UC_RISCV_REG_X28,
    REG_X29 = UC_RISCV_REG_X29,
    REG_X30 = UC_RISCV_REG_X30,
    REG_X31 = UC_RISCV_REG_X31,

    REG_ZERO = UC_RISCV_REG_X0,
    REG_RA  = UC_RISCV_REG_X1,
    REG_SP  = UC_RISCV_REG_X2,
    REG_GP  = UC_RISCV_REG_X3,
    REG_TP  = UC_RISCV_REG_X4,
    REG_RETURN  = UC_RISCV_REG_X10,

    REG_PC = UC_RISCV_REG_PC,
  };

  // Register manipulation
  riscv_addr_t registerGet(Register reg) {
    riscv_addr_t value;
    uc_reg_read(uc_, reg, &value);
    return value;
  }

  void registerSet(Register reg, riscv_addr_t value) {
    uc_reg_write(uc_, reg, &value);
  }

  // Function manipulation
  void functionSkip() {
    registerSet(REG_PC, registerGet(REG_RA));
  }

  void functionSetReturn(riscv_addr_t value) {
    registerSet(REG_RETURN, value);
  }

  riscv_addr_t functionGetArgument(std::size_t n) {
    // Assume each argument is in a different register
    riscv_addr_t value;

    // Might change that the registers are actually one appart in unicorn,
    // this is a safe way (but looks silly)
    switch (n) {
      case 0:
        value = registerGet(REG_X10);
        break;
      case 1:
        value = registerGet(REG_X11);
        break;
      case 2:
        value = registerGet(REG_X12);
        break;
      case 3:
        value = registerGet(REG_X13);
        break;
      case 4:
        value = registerGet(REG_X14);
        break;
      case 5:
        value = registerGet(REG_X15);
        break;
      case 6:
        value = registerGet(REG_X16);
        break;
      case 7:
        value = registerGet(REG_X17);
        break;
      default:
        value = 0;
        std::cerr << "More than 8 funciton arguments are not implemented" << std::endl;
        break;
    }
    return value;
  }

  riscv_addr_t getFunctionAddress(riscv_addr_t address) {
    return address;
  }

};
}
