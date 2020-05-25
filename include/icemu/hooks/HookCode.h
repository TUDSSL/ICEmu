#ifndef ICEMU_HOOKS_HOOKCODE_H_
#define ICEMU_HOOKS_HOOKCODE_H_

#include <iostream> // TODO: remove when making pure virtual

#include "icemu/emu/types.h"
#include "icemu/hooks/Hook.h"

namespace icemu {

class HookCode : public Hook {
  using Hook::Hook;  // Inherit constructor

 public:
  typedef struct hook_arg hook_arg_t;

  virtual void run(hook_arg_t *arg) = 0;
};
}  // namespace icemu

#endif /* ICEMU_HOOKS_HOOKCODE_H_ */
