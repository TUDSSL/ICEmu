#ifndef ICEMU_HOOKS_BUILTIN_HOOKINSTRUCTIONCOUNT_H_
#define ICEMU_HOOKS_BUILTIN_HOOKINSTRUCTIONCOUNT_H_

#include <iostream>

#include "icemu/hooks/HookCode.h"

namespace icemu {

class HookInstructionCount : public HookCode {
 private:
  uint64_t icnt = 0;

 public:
  HookInstructionCount(Emulator &emu) : HookCode(emu, "icnt") {
  }

  ~HookInstructionCount() {
    std::cout << "The program ran for: " << icnt << " instructions" << std::endl;
  }

  void run(hook_arg_t *arg) {
    (void)arg;  // Don't care
    ++icnt;
  }
};
}

#endif /* ICEMU_HOOKS_BUILTIN_HOOKINSTRUCTIONCOUNT_H_ */
