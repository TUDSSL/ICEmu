#ifndef HOOKS_HOOKCODE_H_
#define HOOKS_HOOKCODE_H_

#include "Hook.h"

class HookCode : public Hook {
    using Hook::Hook; // Inherit constructor

    public:
        typedef struct hook_arg hook_arg_t;

        virtual void run(hook_arg_t *arg) {
            std::cout << "[" << arg->address << "] ";
            std::cout << "Running code hook: " << name << std::endl;
        }
};

#endif /* HOOKS_HOOKCODE_H_ */
