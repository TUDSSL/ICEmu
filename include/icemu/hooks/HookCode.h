#ifndef ICEMU_HOOKS_HOOKCODE_H_
#define ICEMU_HOOKS_HOOKCODE_H_

#include <iostream> // TODO: remove when making pure virtual

#include "icemu/emu/types.h"
#include "icemu/hooks/Hook.h"

class HookCode : public Hook {
  using Hook::Hook;  // Inherit constructor

 public:
  typedef struct hook_arg hook_arg_t;

  virtual void run(hook_arg_t *arg) {
    std::cout << "Running code hook: " << name << std::endl;
  }
};

#endif /* ICEMU_HOOKS_HOOKCODE_H_ */
