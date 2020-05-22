#include <iostream>

#include "hooks/hookcode.h"
#include "hooks/hookmanager.h"
#include "hooks/registerhook.h"

using namespace std;

class MyHookCodePlugin : public HookCode {
    public:
        // Hook name, start address and end address
        MyHookCodePlugin() : HookCode("Hook Code Pluging Example", 50, 50) {
            cout << "Constructor my DLL code hook" << endl;
        }

        // Hook run
        void run(hook_arg_t *arg) {
            cout << name << ": run() at address: " << arg->address << endl;
        }
};

// Function that registers the hook
static void registerMyCodeHook(HookManager &HM) {
    HM.add(new MyHookCodePlugin());
}

// Class that is used by ICEmu to finf the register function
// NB. MUST BE NAMED "RegisterMyHook", MUT BE global
RegisterHook RegisterMyHook (registerMyCodeHook);
