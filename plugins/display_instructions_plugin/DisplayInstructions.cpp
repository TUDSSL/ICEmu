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

class DisplayInstructions : public HookCode {
 private:
  const char *format_str;
  std::string printLeader() {
    return "[instr]";
  }

 public:
  // Always execute
  DisplayInstructions(Emulator &emu) : HookCode(emu, "display_instructions") {
    // Store the correct formatting string
    if (getEmulator().getArchitecture().getAddressSize() == 4) {
      // If 32-bit
      format_str = "0x%08lx: %s  %s";
    } else {
      // if 64-bit
      format_str = "0x%016lx: %s  %s";
    }
  }

  ~DisplayInstructions() {
  }

  void displayInstruction(address_t address, address_t size) {
    bool ok;
    uint8_t instruction[size];

    ok = getEmulator().readMemory(address, (char *)instruction, size);
    if (!ok) {
      cerr << printLeader() << " failed to read memory for instruction at address 0x" << hex << address << dec << endl;
      return;
    }
    cs_insn *insn;
    size_t cnt = cs_disasm(*getEmulator().getCapstoneEngine(), instruction, size, address, 0, &insn);
    if (cnt == 0) {
      cerr << printLeader() << " failed to disasemble instruction at address 0x" << hex << address << dec << endl;
      return;
    }

    // Display the actual instruction
    for (size_t i=0; i<cnt; i++) {
      cout << printLeader() << " ";
      printf(format_str, (address_t)insn[i].address, insn[i].mnemonic, insn[i].op_str);
      cout << endl;
    }

    cs_free(insn, cnt);
  }

  // Hook run
  void run(hook_arg_t *arg) {
    displayInstruction(arg->address, arg->size);
  }
};

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  HM.add(new DisplayInstructions(emu));
}

// Class that is used by ICEmu to finf the register function
// NB.  * MUST BE NAMED "RegisterMyHook"
//      * MUST BE global
RegisterHook RegisterMyHook(registerMyCodeHook);
