#ifndef HOOKS_HOOKMEMORY_H_
#define HOOKS_HOOKMEMORY_H_

#include "icemu/types.h"
#include "hook.h"

class HookMemory : public Hook {
    using Hook::Hook; // Inherit constructor

    public:
        enum memory_type {
            MEM_READ,
            MEM_WRITE,
        };

        typedef struct hook_memory_arg : hook_arg {
            enum memory_type mem_type;
            armaddr_t value;
        } hook_arg_t;

        virtual void run(hook_arg_t *arg) {
            std::cout << "[" << arg->address << " <- " << arg->value << "] ";
            std::cout << "Running memory hook: " << name << std::endl;
        }
};

#endif /* HOOKS_HOOKMEMORY_H_ */
