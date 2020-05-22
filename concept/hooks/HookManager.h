#ifndef HOOKS_HOOKMANAGER_H_
#define HOOKS_HOOKMANAGER_H_

#include "icemu/types.h"

#include "Hook.h"
#include "HookCode.h"
#include "HookMemory.h"
#include "Hooks.h"

class HookManager {
    private:
        Hooks<HookCode> hooks_code_;
        Hooks<HookMemory> hooks_memory_;

        // Used for easy cleanup
        std::set<Hook *> hooks_all;
        inline void track_hook(Hook *h) {
            hooks_all.insert(h);
        }

    public:
        typedef std::function<void(HookManager &hb)> ExtensionHookFn;

        HookManager() = default;

        ~HookManager() {
            for (auto h : hooks_all) {
                std::cout << "Deleting: " << h->name << " addr: " << h << std::endl;
                delete h;
            }
        }

        void add(HookCode *hook) {
            std::cout << "Hook Builder adding code hook: " << hook->name << " addr: " << hook <<std::endl;
            track_hook(hook);
            hooks_code_.add(hook);
        }

        void add(HookMemory *hook) {
            std::cout << "Hook Builder adding memory hook: " << hook->name << " addr: " << hook <<std::endl;
            track_hook(hook);
            hooks_memory_.add(hook);
        }

        void run(armaddr_t address, HookCode::hook_arg_t *arg) {
            hooks_code_.run(address, arg);
        }

        void run(armaddr_t address, HookMemory::hook_arg_t *arg) {
            hooks_memory_.run(address, arg);
        }
};

#endif /* HOOKS_HOOKMANAGER_H_ */
