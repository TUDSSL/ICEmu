#ifndef ICEMU_HOOKS_HOOKS_H_
#define ICEMU_HOOKS_HOOKS_H_

#include <iostream>
#include <list>

#include "icemu/emu/types.h"
#include "icemu/hooks/Hook.h"

namespace icemu {

template <class C>
class Hooks {
 private:
  typedef std::list<Hook *> hooklist_t;
  // Hooks that run every time
  hooklist_t hooks;

 public:
  void add(Hook *hook) {
    hooks.push_back(hook);
  }

  template <typename T>
  void run(armaddr_t address, T *arg) {
    // Run the hooks
    hooklist_t::iterator it = hooks.begin();
    while (it != hooks.end()) {
      auto hk = ((C *)*it);

      // Pre hook->run() actions
      auto hk_status = hk->getStatus();
      switch (hk_status) {
        case Hook::STATUS_DISABLED:
          ++it;
          continue;
        //case Hook::STATUS_DELETE:
        //  it = hooks.erase(it);
        //  continue;
        default:
          break;
      }

      if (hk->getType() == Hook::TYPE_ALL) { // Always runs
        hk->run(arg);
      } else if (hk->getType() == Hook::TYPE_RANGE) { // Run if in the range
        if (address >= hk->low && address <= hk->high) { // Fits in range
          hk->run(arg);
        }
      }

      // Post hook->run() actions
      hk_status = hk->getStatus();
      switch (hk_status) {
        case Hook::STATUS_OK:
          ++it;
          break;
        case Hook::STATUS_SKIP_REST:
          it = hooks.end();
          break;
        case Hook::STATUS_ERROR:
          std::cerr << "Hook error in " << hk->name << std::endl;
          ++it;
          break;
        //case Hook::STATUS_DELETE_NOW:
        //  it = hooks.erase(it);
        //  break;
        default:
          std::cerr << "Missed a hook case, moving to the next hook, but check the code" << std::endl;
          ++it;
      }
    }
  }
};
}  // namespace icemu

#endif /* ICEMU_HOOKS_HOOKS_H_ */
