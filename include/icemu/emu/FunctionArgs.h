#ifndef ICEMU_EMU_FUNCTIONARGS_H_
#define ICEMU_EMU_FUNCTIONARGS_H_

/*
 * TODO: Implement all argument options:
 *  - Stack arguments
 *  - Unknown size arguments
 *  - Variadic functions (e.g. printf)
 *  - Struct arguments
 *
 * Arm calling convention
 * https://en.wikipedia.org/wiki/Calling_convention#ARM_(A32)
 */

#include <iostream>
#include <functional>
#include <cstring>

#include "icemu/emu/Registers.h"

namespace icemu {

template<typename T>
class FunctionArg {
 public:
  T arg;
  size_t size;

  FunctionArg() { size = sizeof(arg); }
  FunctionArg(size_t sz) : size(sz) {}

  std::function<void(char *)> parse = [this](const char *virtregbuff) {
    memcpy(&arg, virtregbuff, size);
  };
};

class FunctionArgs {
 private:
  static size_t nreg(size_t sz) {
    size_t rem = sz % 4;
    if (rem == 0)
      return sz/4;
    else
      return (sz + 4 - rem)/4;
  }

  template<typename T>
  static size_t parse(Registers &reg, T &arg, size_t byte_idx) {
    // Even if the size is smaller than a register it takes a complete
    // register. i.e. round to a multiple of 4.
    size_t n_registers = nreg(arg.size);
    size_t start_register = nreg(byte_idx);
    if ((start_register + n_registers) <= 4) {
      char virtregbuff [n_registers*4];

      // The argument is in one of the registers
      for (size_t r=0; r < n_registers; r++) {
          armaddr_t r_content = reg.get(r+start_register);
          memcpy(&virtregbuff[r*4], &r_content, 4);
      }
      arg.parse(virtregbuff);
      byte_idx += 4; // Registers always count as 32-bit
    } else {
      std::cerr << "[FunctionArgs] Arguments don't fit int the registers, "
                   "parsing not implenented"
                << std::endl;
      return 0;
    }

    return byte_idx;
  }

  template<typename T, typename... Args>
  static size_t parse(Registers &reg, size_t byte_idx, T &a, Args... args) {
    byte_idx = parse(reg, a, byte_idx);
    return parse(reg, byte_idx, args...);
  }

  static inline size_t parse(Registers &reg, size_t byte_idx) {
    (void)reg;
    return byte_idx;
  }

 public:
  template<typename... Args>
  static bool parse(Registers &reg, Args... args) {
    size_t byte_idx = 0;
    parse(reg, byte_idx, args...);
    return true;
  }

};

}  // namespace icemu

#endif /* ICEMU_EMU_FUNCTIONARGS_H_ */
