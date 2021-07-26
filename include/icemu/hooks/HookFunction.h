#ifndef ICEMU_HOOKS_HOOKFUNCTION_H_
#define ICEMU_HOOKS_HOOKFUNCTION_H_

#include <iostream> // TODO: remove when making pure virtual

#include "icemu/emu/types.h"
#include "icemu/hooks/Hook.h"
#include "icemu/hooks/HookCode.h"
#include "icemu/emu/Emulator.h"

namespace icemu {

class HookFunction : public HookCode {
 public:
  std::string function_name;

  HookFunction(Emulator &emu, std::string fname)
      : HookCode(emu, "hook_function_" + fname) {
    function_name = fname;
    try {
      auto func_addr = getEmulator()
                           .getMemory()
                           .getSymbols()
                           .get(function_name)
                           ->getFuncAddr();
      type = Hook::TYPE_RANGE;
      low = high = func_addr;
    } catch (...) {
      std::cerr << "Failed to register function hook for: " << function_name
                << " (UNKNOWN ADDRESS)" << std::endl;
      setStatus(Hook::STATUS_ERROR);
      return;
    }
  }

  // Helper
  inline Registers &getRegisters() { return getEmulator().getRegisters(); }

  virtual void run(hook_arg_t *arg) = 0;
};
}  // namespace icemu

#endif /* ICEMU_HOOKS_HOOKFUNCTION_H_ */

