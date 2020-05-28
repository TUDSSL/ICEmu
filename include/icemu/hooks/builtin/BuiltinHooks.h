#ifndef ICEMU_HOOKS_BUILDIN_BUILTINHOOKS_H_
#define ICEMU_HOOKS_BUILDIN_BUILTINHOOKS_H_

#include "icemu/hooks/HookManager.h"
#include "icemu/hooks/builtin/HookInstructionCount.h"
#include "icemu/hooks/builtin/HookStopEmulation.h"
#include "icemu/hooks/builtin/HookControlRegisters.h"

namespace icemu {

namespace BuiltinHooks {

  void registerHooks(Emulator &emu, HookManager &hm) {
    hm.add(new HookInstructionCount(emu)); // Instruction count hook
    hm.add(new HookControlRegisters(emu)); // Handle control register access
    hm.add(new HookStopEmulation(emu)); // Stop emulation hook
  }

}

}


#endif /* ICEMU_HOOKS_BUILDIN_BUILTINHOOKS_H_ */
