#include <iostream>
#include "hooks.h"

#include <boost/dll.hpp>

using namespace std;

//extern RegisterCodeHook RegisterMyHook;

class MyCodeHookLocal : public HookCode {
    public:
        MyCodeHookLocal() : HookCode ("My Code Hook Local", 10, 10) {
            cout << "Constructor my code hook local" << endl;;
            cout << "My code hook name = " << name << endl;
        }

        void run(hook_arg_t *arg) {
            cout << "My code hook local: " << name << endl;
        }
};


int main()
{
    cout << "Hooks test" << endl;
    //HookCode hook_code("Hook Code", 10, 100);
    HookMemory *hook_mem_1 = new HookMemory("Hook Memory 1", 10, 100);
    //HookMemory hook_mem_2("Hook Memory 2", 9, 9);
    HookMemory *hook_mem_2 = new HookMemory;
    hook_mem_2->name = "Hook Memory 2";
    hook_mem_2->low = 9;
    hook_mem_2->high = 9;
    hook_mem_2->type = HookMemory::RANGE;

    Hooks<HookCode> code_hooks;
    Hooks<HookMemory> memory_hooks;

    //code_hooks.add(&hook_code);
    //memory_hooks.add(hook_mem_1);
    //memory_hooks.add(hook_mem_2);

    // Add local hook
    //code_hooks.add(new MyCodeHookLocal());

    cout << "Hook mem 1 address: " << hook_mem_1 << endl;
    HookManager HM(code_hooks, memory_hooks);

    HM.add(hook_mem_1);
    HM.add(hook_mem_2);

    // Add dll hook
    boost::dll::shared_library lib("dll.so");
    RegisterHook *rch = &lib.get<RegisterHook>("RegisterMyHook");
    cout << "Address: " << rch << endl;
    rch->reg(HM);

    boost::dll::shared_library lib2("dll.so");
    RegisterHook *rch2 = &lib2.get<RegisterHook>("RegisterMyHook");
    cout << "Address: " << rch2 << endl;
    rch2->reg(HM);

    //RegisterMyHook.reg(HM);

    // Test the hooks
    cout << "Test hooks" << endl;

    list<armaddr_t> addr = {0, 9, 10, 50, 100, 101, 200};

    for (const auto &a : addr) {
        cout << "Code Address: " << a << endl;
        HookCode::hook_arg_t arg;
        arg.address = a;
        //code_hooks.run<HookCode>(a, &arg);
        code_hooks.run(a, &arg);
    }

    for (const auto &a : addr) {
        cout << "Mem Address: " << a << endl;
        HookMemory::hook_arg_t arg;
        arg.address = a;
        arg.value = 42;
        //memory_hooks.run<HookMemory>(a, &arg);
        memory_hooks.run(a, &arg);
    }

    cout << "END Hook mem 1 address: " << hook_mem_1 << endl;
}

