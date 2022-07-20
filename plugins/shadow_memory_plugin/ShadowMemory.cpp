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
  std::string printLeader() { return "[shadowmem]"; }

  // Option
  bool print_mem_diff = true;

  memseg_t *MainMemSegment = nullptr;
  uint8_t *ShadowMem = nullptr;

  bool compareMemory() {
    // First do a fast memcmp (assume it's optimized)
    if (memcmp(ShadowMem, MainMemSegment->data, MainMemSegment->length) == 0) {
      // Memory is the same
      return true;
    }

    // Something is different according to `memcmp`, check byte-per-byte
    bool same = true;
    for (size_t i = 0; i < MainMemSegment->length; i++) {
      if (ShadowMem[i] != MainMemSegment->data[i]) {
        // Memory is different
        same = false;

        if (print_mem_diff) {
          address_t addr = MainMemSegment->origin + i;
          address_t emu_val = MainMemSegment->data[i];
          address_t shadow_val = ShadowMem[i];
          cerr << printLeader() << " memory location at 0x" << hex << addr
               << " differ - Emulator: 0x" << emu_val << " Shadow: 0x"
               << shadow_val << dec << endl;
        }
      }
    }
    return same;
  }

  void shadowWrite(address_t address, address_t value, address_t size) {
    address_t address_idx = address - MainMemSegment->origin;
    for (address_t i=0; i<size; i++) {
      uint64_t byte = (value >>(8*i)) & 0xFF; // Get the bytes
      ShadowMem[address_idx+i] = byte;
    }
  }

 public:
  // Always execute
  DisplayMemory(Emulator &emu) : HookMemory(emu, "display_memory") {
    auto code_entrypoint = getEmulator().getMemory().entrypoint;
    // Get the memory segment holding the main code (assume it also holds the RAM)
    MainMemSegment = getEmulator().getMemory().find(code_entrypoint);
    assert(MainMemSegment != nullptr);

    // Create shadow memory
    ShadowMem = new uint8_t[MainMemSegment->length];
    assert(ShadowMem != nullptr);

    // Populate the shadow memory
    memcpy(ShadowMem, MainMemSegment->data, MainMemSegment->length);
  }

  ~DisplayMemory() {
    compareMemory(); // a final check
    delete[] ShadowMem;
  }

  // Hook run
  void run(hook_arg_t *arg) {
    // Check if the shadow memory matches the emulator memory
    compareMemory();

    switch(arg->mem_type) {
      case MEM_READ:
        // Nothing
        break;
      case MEM_WRITE:
        shadowWrite(arg->address, arg->value, arg->size);
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
