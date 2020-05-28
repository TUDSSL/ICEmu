#ifndef ICEMU_HOOKS_BUILTIN_HOOKSTOPEMULATION_H_
#define ICEMU_HOOKS_BUILTIN_HOOKSTOPEMULATION_H_

#include <atomic>
#include <iostream>

#include "icemu/emu/Emulator.h"
#include "icemu/hooks/HookCode.h"

namespace icemu {

extern volatile std::atomic<bool> gStopEmulation;

class HookStopEmulation : public HookCode {
 private:
  const uint16_t breakpoint_instr = 0xbe00;

 public:
  HookStopEmulation(Emulator &emu) : HookCode(emu, "stop_emulation") {
  }

  ~HookStopEmulation() {
  }

  void run(hook_arg_t *arg) {
    (void)arg;
    if (gStopEmulation == true) {
      getEmulator().stop("Stop signal received");
      setStatus(Hook::STATUS_SKIP_REST);
      return;
    }
    uint16_t instr;
    if (getEmulator().readMemory(arg->address, (char *)&instr, sizeof(instr))) {
      if (instr == breakpoint_instr) {
        getEmulator().stop("Breakpoint instruction");
        setStatus(Hook::STATUS_SKIP_REST);
      }
    } else {
      std::cerr << "Could not read instruction memory" << std::endl;
      getEmulator().stop("Could not read instruction");
      setStatus(Hook::STATUS_SKIP_REST);
    }
  }
};
}


#endif /* ICEMU_HOOKS_BUILTIN_HOOKSTOPEMULATION_H_ */
