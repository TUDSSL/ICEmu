#ifndef ICEMU_HOOKS_HOOK_H_
#define ICEMU_HOOKS_HOOK_H_

#include <string>

#include "icemu/emu/types.h"

namespace icemu {

class Emulator;

// Base class
class Hook {
 public:
  enum hook_type {
    UNINITIALIZED,
    RANGE,
    ALL,
  };

  enum hook_status {
    STATUS_OK,        // All OK
    STATUS_SKIP_REST, // Skip the rest of the hooks (only includes
    STATUS_DISABLED,  // Disable this hook, can only be enabled by another hook
    STATUS_ERROR,     // An error occurred while running the hook
    STATUS_DELETE,    // Delete the hook after processing all hooks (at the start
                      // of the new round, so if any hooks depend on it they are
                      // serviced first
  };

  struct hook_arg {
    armaddr_t address;
    armaddr_t size;
  };

  std::string name;
  armaddr_t low;
  armaddr_t high;
  enum hook_type type = UNINITIALIZED;

  explicit Hook(Emulator &emu, std::string hookname, armaddr_t addrlow, armaddr_t addrhigh) : emu_(emu) {
    type = RANGE;
    name = hookname;
    low = addrlow;
    high = addrhigh;
  }

  explicit Hook(Emulator &emu, std::string hookname) : emu_(emu) {
    type = ALL;
    name = hookname;
  }

  // Make sure we can delete the base class and that will delete the derived
  // class
  virtual ~Hook() = default;

  inline Emulator &getEmulator() { return emu_; }

  inline void setStatus(enum hook_status hs) { hs_ = hs; }

  inline enum hook_status getStatus(void) { return hs_; }

 private:
  Emulator &emu_;
  enum hook_status hs_ = STATUS_OK;

};
}  // namespace icemu

#endif /* ICEMU_HOOKS_HOOK_H_ */
