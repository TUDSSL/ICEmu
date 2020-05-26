#ifndef ICEMU_HOOKS_HOOK_H_
#define ICEMU_HOOKS_HOOK_H_

#include <string>

#include "icemu/emu/types.h"

namespace icemu {

class Emulator;

// Base class
class Hook {
 private:
  Emulator &emu_;

 public:
  enum hook_type {
    UNINITIALIZED,
    RANGE,
    ALL,
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
};
}  // namespace icemu

#endif /* ICEMU_HOOKS_HOOK_H_ */
