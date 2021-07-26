#ifndef ICEMU_EMU_FUNCTION_H_
#define ICEMU_EMU_FUNCTION_H_

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

class Function {
 public:
  static void setReturn(Registers &reg, armaddr_t value) { reg.set(0, value); }

  static armaddr_t toFuncAddr(armaddr_t address) {
    return address | 0x1;
  }

  static void skip(Registers &reg) {
    reg.set(Registers::PC, toFuncAddr(reg.get(Registers::LR)));
  }

  static void skip(Registers &reg, armaddr_t return_value) {
    skip(reg);
    setReturn(reg, return_value);
  }

  // Special (rare) case
  static void setReturn64(Registers &reg, uint64_t value) {
    reg.set(0, value & ((1UL<<32)-1));
    reg.set(1, value >> 32);
  }

  template <typename T>
  class Argument {
   public:
    T arg = 0;
    size_t size;

    Argument() { size = sizeof(arg); }
    Argument(size_t sz) : size(sz) {}

    std::function<void(char *)> parse = [this](const char *virtregbuff) {
      memcpy(&arg, virtregbuff, size);
    };
  };

  class Arguments {
   private:
    static size_t nreg(size_t sz) {
      size_t rem = sz % 4;
      if (rem == 0)
        return sz / 4;
      else
        return (sz + 4 - rem) / 4;
    }

    template <typename T>
    static size_t parse(Registers &reg, T &arg, size_t byte_idx) {
      // Even if the size is smaller than a register it takes a complete
      // register. i.e. round to a multiple of 4.
      size_t n_registers = nreg(arg.size);
      size_t start_register = nreg(byte_idx);
      if ((start_register + n_registers) <= 4) {
        char virtregbuff[n_registers * 4];

        // The argument is in one of the registers
        for (size_t r = 0; r < n_registers; r++) {
          armaddr_t r_content = reg.get(r + start_register);
          memcpy(&virtregbuff[r * 4], &r_content, 4);
        }
        arg.parse(virtregbuff);
        byte_idx += 4;  // Registers always count as 32-bit
      } else {
        std::cerr << "[FunctionArgs] Arguments don't fit int the registers, "
                     "parsing not implenented"
                  << std::endl;
        return 0;
      }

      return byte_idx;
    }

    template <typename T, typename... Args>
    static size_t parse(Registers &reg, size_t byte_idx, T &a, Args... args) {
      byte_idx = parse(reg, a, byte_idx);
      return parse(reg, byte_idx, args...);
    }

    static inline size_t parse(Registers &reg, size_t byte_idx) {
      (void)reg;
      return byte_idx;
    }

   public:
    template <typename... Args>
    static bool parse(Registers &reg, Args... args) {
      size_t byte_idx = 0;
      parse(reg, byte_idx, args...);
      return true;
    }
  };

  class FunctionReturn {
   public:
    static void set(Registers &reg, armaddr_t value) { reg.set(0, value); }
  };
};

}  // namespace icemu

#endif /* ICEMU_EMU_FUNCTION_H_ */
