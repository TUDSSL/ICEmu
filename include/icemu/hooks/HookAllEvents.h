#ifndef ICEMU_HOOKS_HOOKALLEVENTS_H_
#define ICEMU_HOOKS_HOOKALLEVENTS_H_

#include <iostream> // TODO: remove when making pure virtual

#include "icemu/emu/types.h"
#include "icemu/hooks/Hook.h"
#include "icemu/hooks/HookMemory.h"

namespace icemu {

class HookAllEvents : public Hook {
  using Hook::Hook;  // Inherit constructor

 public:
  enum event_type {
    EVENT_UNKNOWN,
    EVENT_CODE,
    EVENT_MEMORY,
  };

  typedef struct hook_all_events_arg : hook_arg {
    enum event_type event_type;
    enum HookMemory::memory_type mem_type;
    address_t value;
  } hook_arg_t;

  virtual void run(hook_arg_t *arg) {
    std::cout << "[" << arg->address << " <- " << arg->value << "] ";
    std::cout << "Running 'all events' hook: " << name << std::endl;
  }
};
}  // namespace icemu

#endif /* ICEMU_HOOKS_HOOKALLEVENTS_H_ */
