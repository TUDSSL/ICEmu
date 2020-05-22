#ifndef ICEMU_HOOKS_HOOKMEMORY_H_
#define ICEMU_HOOKS_HOOKMEMORY_H_

#include "icemu/types.h"
#include "icemu/hooks/Hook.h"

class HookMemory : public Hook {
  using Hook::Hook;  // Inherit constructor

 public:
  enum memory_type {
    MEM_READ,
    MEM_WRITE,
  };

  typedef struct hook_memory_arg : hook_arg {
    enum memory_type mem_type;
    armaddr_t value;
  } hook_arg_t;

  virtual void run(hook_arg_t *arg) {
    std::cout << "[" << arg->address << " <- " << arg->value << "] ";
    std::cout << "Running memory hook: " << name << std::endl;
  }
};

#endif /* ICEMU_HOOKS_HOOKMEMORY_H_ */
