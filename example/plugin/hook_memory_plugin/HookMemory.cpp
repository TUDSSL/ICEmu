/**
 *  ICEmu loadable plugin (library)
 *
 * An example ICEmu plugin that is dynamically loaded.
 * This example prints the address of each instruction that is executed.
 *
 * Should be compiled as a shared library, i.e. using `-shared -fPIC`
 */
#include <iostream>

#include "icemu/emu/Emulator.h"
#include "icemu/hooks/HookMemory.h"
#include "icemu/hooks/HookManager.h"
#include "icemu/hooks/RegisterHook.h"

using namespace std;
using namespace icemu;

class MyHookCodePlugin : public HookMemory {
 public:
  // No address range would always execute
  MyHookCodePlugin(Emulator &emu) : HookMemory(emu, "Hook Memory Pluging Example") {
    cout << "Constructor my DLL memory hook" << endl;
  }

  // Hook run
  void run(hook_arg_t *arg) {
    switch (arg->mem_type) {
      case MEM_READ:
        cout << "Memory READ access at address: 0x" << hex << arg->address << dec << endl;
        break;
      case MEM_WRITE:
        cout << "Memory WRITE access at address: 0x" << hex << arg->address << dec << endl;
        break;
    }
  }
};

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  HM.add(new MyHookCodePlugin(emu));
}

// Class that is used by ICEmu to finf the register function
// NB.  * MUST BE NAMED "RegisterMyHook"
//      * MUST BE global
RegisterHook RegisterMyHook(registerMyCodeHook);
