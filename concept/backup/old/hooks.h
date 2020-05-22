#ifndef HOOKS_H_
#define HOOKS_H_

#include <iostream>
#include <boost/icl/interval_map.hpp>

#include <list>
#include <cstdint>

#include <boost/icl/interval_set.hpp>

//typedef void (*uc_cb_hookmem_t)(uc_engine *uc, uc_mem_type type,
//        uint64_t address, int size, int64_t value, void *user_data);

// typedef void (*uc_cb_hookcode_t)(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);


typedef uint32_t armaddr_t;

// Base class
class Hook {
    public:
        enum hook_type {
            UNINITIALIZED,
            RANGE,
            ALL,
        };

        struct hook_arg {
            //Emulator *emu;
            armaddr_t address;
            armaddr_t size;
        };

        std::string name;
        armaddr_t low;
        armaddr_t high;
        enum hook_type type = UNINITIALIZED;

        explicit Hook(std::string hookname, armaddr_t addrlow, armaddr_t addrhigh) {
            type = RANGE;
            name = hookname;
            low = addrlow;
            high = addrhigh;
        }

        explicit Hook(std::string hookname) {
            type = ALL;
            name = hookname;
        }

        explicit Hook() = default;

        //virtual void run(void) {
        //    std::cout << "Running base hook: " << name << std::endl;
        //}

        // Make sure we can delete the base class and that will delete the derived class
        virtual ~Hook() = default;
};

/*
 * Code Hook
 * Alias, currently the same as the base class
 */
class HookCode : public Hook {
    using Hook::Hook; // Inherit constructor

    public:
        typedef struct hook_arg hook_arg_t;

        virtual void run(hook_arg_t *arg) {
            std::cout << "[" << arg->address << "] ";
            std::cout << "Running code hook: " << name << std::endl;
        }
};

/*
 * Memory Hook
 */
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


template <class C>
class Hooks {
    private:
        typedef boost::icl::interval<armaddr_t> hookinterval_t;
        typedef std::set<Hook *> hookset_t;
        typedef boost::icl::interval_map<armaddr_t, hookset_t> interval_hookset_t;

        hookset_t hooks_all;
        interval_hookset_t hooks_interval;

    public:
        void add(Hook *hook) {
            hooks_interval.add(
                    make_pair(hookinterval_t::closed(hook->low, hook->high), hookset_t {hook})
                    );
        }

        template <typename T> void run(armaddr_t address, T *arg) {
            for (const auto &h : hooks_interval(address)) {
                ((C *)h)->run(arg);
            }
        }
};

class HookManager {
    private:
        Hooks<HookCode> &hooks_code_;
        Hooks<HookMemory> &hooks_memory_;

        // Used for easy cleanup
        std::set<Hook *> hooks_all;
        inline void track_hook(Hook *h) {
            hooks_all.insert(h);
        }

    public:
        typedef std::function<void(HookManager &hb)> ExtensionHookFn;

        HookManager(Hooks<HookCode> &hooks_code, Hooks<HookMemory> &hooks_memory)
            : hooks_code_(hooks_code), hooks_memory_(hooks_memory) {};

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
};

class RegisterHook {
    public:
        HookManager::ExtensionHookFn reg;
        RegisterHook(HookManager::ExtensionHookFn f) : reg(f) {};
};

#endif /* HOOKS_H_ */
