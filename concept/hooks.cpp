#include <iostream>

#include "hooks/HookCode.h"
#include "hooks/HookMemory.h"
#include "hooks/HookManager.h"
#include "hooks/RegisterHook.h"

#include <boost/dll.hpp>

using namespace std;



int main()
{
    cout << "Hooks test" << endl;


    HookManager HM;

    // Add local hook
    HookMemory *hook_mem = new HookMemory("Hook Memory 1", 10, 100);
    HM.add(hook_mem);

    HookMemory *hook_code = new HookMemory("Hook Code 1", 9, 11);
    HM.add(hook_code);

    // Add dll hook
    boost::dll::shared_library lib("HookCodePlugin.so");
    RegisterHook *rch = &lib.get<RegisterHook>("RegisterMyHook");
    rch->reg(HM);

    // Test the hooks
    cout << "Test hooks" << endl;

    list<armaddr_t> addr = {0, 9, 10, 50, 100, 101, 200};

    for (const auto &a : addr) {
        cout << "Code Address: " << a << endl;
        HookCode::hook_arg_t arg;
        arg.address = a;
        HM.run(a, &arg);
    }

    for (const auto &a : addr) {
        cout << "Mem Address: " << a << endl;
        HookMemory::hook_arg_t arg;
        arg.address = a;
        arg.value = 42;
        HM.run(a, &arg);
    }

}

