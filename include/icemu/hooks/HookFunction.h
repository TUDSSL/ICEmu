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
  address_t function_address;

  HookFunction(Emulator &emu, std::string fname)
      : HookCode(emu, "hook_function_" + fname) {
    function_name = fname;
    try {
      function_address = getEmulator()
                           .getMemory()
                           .getSymbols()
                           .get(function_name)
                           ->address;
      function_address = emu.getArchitecture().getFunctionAddress(function_address);

      type = Hook::TYPE_RANGE;
      low = high = function_address;
    } catch (...) {
      std::cerr << "Failed to register function hook for: " << function_name
                << " (UNKNOWN ADDRESS)" << std::endl;
      setStatus(Hook::STATUS_ERROR);
      return;
    }
  }

  // Helper
  inline Architecture &getArchitecture() { return getEmulator().getArchitecture(); }
  inline address_t &getFunctionAddress() { return function_address; }

  virtual void run(hook_arg_t *arg) = 0;
};
}  // namespace icemu

#endif /* ICEMU_HOOKS_HOOKFUNCTION_H_ */

