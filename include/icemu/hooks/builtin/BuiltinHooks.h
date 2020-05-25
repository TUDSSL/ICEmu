#ifndef ICEMU_HOOKS_BUILDIN_BUILTINHOOKS_H_
#define ICEMU_HOOKS_BUILDIN_BUILTINHOOKS_H_

#include "icemu/hooks/HookManager.h"
#include "icemu/hooks/builtin/HookInstructionCount.h"

namespace icemu {

namespace BuiltinHooks {

  void registerHooks(HookManager &hm) {
    hm.add(new HookInstructionCount()); // Instruction count hook
  }

}

}


#endif /* ICEMU_HOOKS_BUILDIN_BUILTINHOOKS_H_ */
