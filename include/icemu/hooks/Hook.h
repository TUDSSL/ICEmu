#ifndef ICEMU_HOOKS_HOOK_H_
#define ICEMU_HOOKS_HOOK_H_

#include "icemu/types.h"

// Base class
class Hook {
 public:
  enum hook_type {
    UNINITIALIZED,
    RANGE,
    ALL,
  };

  struct hook_arg {
    // Emulator *emu;
    armaddr_t address;
    armaddr_t size;
  };

  std::string name;
  armaddr_t low;
  armaddr_t high;
  enum hook_type type = UNINITIALIZED;

  explicit Hook(std::string hookname, armaddr_t addrlow, armaddr_t addrhigh) {
    type = RANGE;
    name = hookname;
    low = addrlow;
    high = addrhigh;
  }

  explicit Hook(std::string hookname) {
    type = ALL;
    name = hookname;
  }

  explicit Hook() = default;

  // Make sure we can delete the base class and that will delete the derived
  // class
  virtual ~Hook() = default;
};

#endif /* ICEMU_HOOKS_HOOK_H_ */
