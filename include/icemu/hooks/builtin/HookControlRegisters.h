#ifndef ICEMU_HOOKS_BUILTIN_HOOKCONTROLREGISTERS_H_
#define ICEMU_HOOKS_BUILTIN_HOOKCONTROLREGISTERS_H_

#include <iostream>

#include "icemu/hooks/HookMemory.h"
#include "icemu/emu/Emulator.h"

namespace icemu {



class HookControlRegisters : public HookMemory {
 private:
  const std::string memory_segment_name = "SYSTEM_CONTROL_REGISTERS";


 public:
  HookControlRegisters(Emulator &emu) : HookMemory(emu, "ctrl-reg") {
    type = TYPE_RANGE;
    // Need to modify some options
    std::cout << "Get the memory segment" << std::endl;
    memseg_t *memseg = emu.getMemory().find(memory_segment_name);
    if (memseg == NULL) {
      std::cerr << "Did not find the memory segment: " << memory_segment_name << std::endl;
      return;
    }
    low = memseg->origin;
    high = low + memseg->length;

    // TODO: Configure the default values in memory
    // VTOR happens to be zero at boot, and we zero all the memory
    // But for this we need to have a nicer "getMemoryPointer" or something

  }

  ~HookControlRegisters() {
  }

  void run(hook_arg_t *arg) {
    armaddr_t addr = arg->address;

    if (arg->mem_type == HookMemory::MEM_READ) {
      std::cout << "[CTRL-REGISTER] read" << std::endl;
      if (addr == 0xE000ED08) {
        std::cout << "VTOR: " << arg->value << std::endl;
      }
    } else if (arg->mem_type == HookMemory::MEM_WRITE) {
      std::cout << "[CTRL-REGISTER] write" << std::endl;
      if (addr == 0xE000ED08) {
        std::cout << "VTOR: " << arg->value << std::endl;
      }
    } else {
      std::cout << "[CTRL-REGISTER] UNKNOWN TYPE" << std::endl;
      //getEmulator().stop();
    }
  }
};
}

#endif /* ICEMU_HOOKS_BUILTIN_HOOKCONTROLREGISTERS_H_ */
