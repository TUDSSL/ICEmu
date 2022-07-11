#pragma once

#include <cstdint>
#include <iostream>
#include <assert.h>

#include <unicorn/unicorn.h>

#include "Arch.h"
#include "ArchitectureArmv7.h"
#include "ArchitectureRiscv64.h"

namespace icemu {
/*
 * Wrapper class that dynamically chooses the helpers from the correct architecture
 * TODO: Probably make an abstract base class somewhere to not have the switch-case.
 */
class Architecture {
 private:
  // The current architecture
  Arch arch_;

  // Unicorn emulator engine
  uc_engine *uc_ = nullptr;

  // Availible architectures
  ArchitectureArmv7 arch_armv7;
  ArchitectureRiscv64 arch_riscv64;

  // Map

 public:

  void init(Arch arch, uc_engine *uc) {
    arch_ = arch;
    uc_ = uc;

    // Init the availible architectures
    arch_armv7.init(uc);
    arch_riscv64.init(uc);
  }

  // Architecture
  inline Arch getArch() { return arch_; }

  // Generic registers
  enum Register {
    REG_RETURN,
    REG_RETURN_ADDRESS,
    REG_PC,
    REG_SP
  };

  ArchitectureArmv7::Register genericRegToArmv7Reg(Register reg) {
    switch (reg) {
      case REG_RETURN:
        return ArchitectureArmv7::REG_RETURN;
      case REG_RETURN_ADDRESS:
        return ArchitectureArmv7::REG_LR;
      case REG_PC:
        return ArchitectureArmv7::REG_PC;
      case REG_SP:
        return ArchitectureArmv7::REG_SP;
    }
    assert(false && "Unknown register map between generic register and ARMv7 register");
  }

  ArchitectureRiscv64::Register genericRegToRiscv64Reg(Register reg) {
    switch (reg) {
      case REG_RETURN:
        return ArchitectureRiscv64::REG_RETURN;
      case REG_RETURN_ADDRESS:
        return ArchitectureRiscv64::REG_RA;
      case REG_PC:
        return ArchitectureRiscv64::REG_PC;
      case REG_SP:
        return ArchitectureRiscv64::REG_SP;
    }
    assert(false && "Unknown register map between generic register and RISCV64 register");
  }
  
  int genericToArchReg(Register reg) {
    switch (arch_) {
      case EMU_ARCH_ARMV7:
        return genericRegToArmv7Reg(reg);
        break;
      case EMU_ARCH_RISCV64:
        return genericRegToRiscv64Reg(reg);
        break;
    }
    assert(false && "Unknown architecture");
  }

  // Register size
  inline address_t getAddressSize() {
    switch (arch_) {
      case EMU_ARCH_ARMV7:
        return arch_armv7.getAddressSize();
        break;
      case EMU_ARCH_RISCV64:
        return arch_riscv64.getAddressSize();
        break;
    }
    assert(false && "Unknown architecture");
  }

  address_t registerGet(Register reg) {
    address_t value = 0;
    uc_reg_read(uc_, genericToArchReg(reg), &value);
    return value;
  }

  void registerSet(Register reg, address_t value) {
    uc_reg_write(uc_, genericToArchReg(reg), &value);
  }

  // Function manipulation
  void functionSkip() {
    switch (arch_) {
      case EMU_ARCH_ARMV7:
        arch_armv7.functionSkip();
        break;
      case EMU_ARCH_RISCV64:
        arch_riscv64.functionSkip();
        break;
    }
  }

  void functionSetReturn(uint64_t value) {
    switch (arch_) {
      case EMU_ARCH_ARMV7:
        arch_armv7.functionSetReturn(value);
        break;
      case EMU_ARCH_RISCV64:
        arch_riscv64.functionSetReturn(value);
        break;
    }
  }

  void functionSetReturn(uint32_t value) {
    switch (arch_) {
      case EMU_ARCH_ARMV7:
        arch_armv7.functionSetReturn(value);
        break;
      case EMU_ARCH_RISCV64:
        arch_riscv64.functionSetReturn(value);
        break;
    }
  }

  void functionSetReturn(uint16_t value) {
    functionSetReturn((uint32_t)value);
  }

  void functionSetReturn(uint8_t value) {
    functionSetReturn((uint32_t)value);
  }


  address_t functionGetArgument(std::size_t n) {
    switch (arch_) {
      case EMU_ARCH_ARMV7:
        return arch_armv7.functionGetArgument(n);
        break;
      case EMU_ARCH_RISCV64:
        return arch_riscv64.functionGetArgument(n);
        break;
    }
    assert(false && "Unknown architecture");
  }

  address_t getFunctionAddress(address_t address) {
    switch (arch_) {
      case EMU_ARCH_ARMV7:
        return arch_armv7.getFunctionAddress(address);
        break;
      case EMU_ARCH_RISCV64:
        return arch_riscv64.getFunctionAddress(address);
        break;
    }
    assert(false && "Unknown architecture");
  }

#if 0 // is this needed?
  void reset() {
    switch (arch_) {
      case EMU_ARCH_ARMV7:
        return arch_armv7.reset();
        break;
      case EMU_ARCH_RISCV64:
        return arch_riscv64.reset(n);
        break;
    }
    assert(false && "Unknown architecture");
  }
#endif
};
}
