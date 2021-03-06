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
  }
};
}


#endif /* ICEMU_HOOKS_BUILTIN_HOOKSTOPEMULATION_H_ */
