/**
 *  ICEmu loadable plugin (library)
 *
 * An example ICEmu plugin that is dynamically loaded.
 * This example prints the disassembled instructions
 *
 * Should be compiled as a shared library, i.e. using `-shared -fPIC`
 */
#include <iostream>

#include "capstone/capstone.h"

#include "icemu/emu/types.h"
#include "icemu/emu/Emulator.h"
#include "icemu/hooks/HookCode.h"
#include "icemu/hooks/HookManager.h"
#include "icemu/hooks/RegisterHook.h"

using namespace std;
using namespace icemu;

class DisplayMemory : public HookMemory {
 private:
  std::string printLeader() {
    return "[mem]";
  }

 public:
  // Always execute
  DisplayMemory(Emulator &emu) : HookMemory(emu, "display_memory") {
  }

  ~DisplayMemory() {
  }

  // Hook run
  void run(hook_arg_t *arg) {
    char *m = getEmulator().getMemory().at(arg->address&0xFFFFFFFF);
    uint64_t value = 0;
    memcpy(&value, m, arg->size);

    switch(arg->mem_type) {
      case MEM_READ:
        cout << printLeader() << " READ size: " << arg->size << " at 0x" << hex << arg->address << dec << " val: " << value << endl;
        break;
      case MEM_WRITE:
        cout << printLeader() << " WRITE size: " << arg->size << " at 0x" << hex << arg->address << dec << " val: " << arg->value << endl;
        break;
    }
  }
};

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  HM.add(new DisplayMemory(emu));
}

// Class that is used by ICEmu to finf the register function
// NB.  * MUST BE NAMED "RegisterMyHook"
//      * MUST BE global
RegisterHook RegisterMyHook(registerMyCodeHook);
