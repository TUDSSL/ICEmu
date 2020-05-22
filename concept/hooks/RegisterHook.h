#ifndef HOOKS_REGISTERHOOK_H_
#define HOOKS_REGISTERHOOK_H_

#include "HookManager.h"

class RegisterHook {
    public:
        HookManager::ExtensionHookFn reg;
        RegisterHook(HookManager::ExtensionHookFn f) : reg(f) {};
};

#endif /* HOOKS_REGISTERHOOK_H_ */
