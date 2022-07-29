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
#include "icemu/hooks/HookAllEvents.h"
#include "icemu/hooks/HookManager.h"
#include "icemu/hooks/RegisterHook.h"

using namespace std;
using namespace icemu;

class MyHookCodePlugin : public HookAllEvents {
 public:
  // No address range would always execute
  MyHookCodePlugin(Emulator &emu) : HookAllEvents(emu, "Hook Memory Pluging Example") {
    cout << "Constructor my DLL memory hook" << endl;
  }

  // Hook run
  void run(hook_arg_t *arg) {
    if (arg->event_type == EVENT_MEMORY) {
      switch (arg->mem_type) {
        case HookMemory::MEM_READ:
          cout << "Memory READ access at address: 0x" << hex << arg->address << dec << endl;
          break;
        case HookMemory::MEM_WRITE:
          cout << "Memory WRITE access at address: 0x" << hex << arg->address << dec << endl;
          break;
      }
    }

    else if (arg->event_type == EVENT_CODE) {
      cout << "Executing instruction at address: 0x" 
           << hex << arg->address << dec << endl;
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
