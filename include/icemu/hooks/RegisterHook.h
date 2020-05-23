#ifndef HOOKS_REGISTERHOOK_H_
#define HOOKS_REGISTERHOOK_H_

#include "icemu/hooks/HookManager.h"

namespace icemu {

class RegisterHook {
 public:
  HookManager::ExtensionHookFn reg;
  RegisterHook(HookManager::ExtensionHookFn f) : reg(f){};
};

}  // namespace icemu

#endif /* HOOKS_REGISTERHOOK_H_ */
