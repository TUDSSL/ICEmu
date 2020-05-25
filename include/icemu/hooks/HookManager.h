#ifndef ICEMU_HOOKS_HOOKMANAGER_H_
#define ICEMU_HOOKS_HOOKMANAGER_H_

#include <set>
#include <iostream>

#include "icemu/emu/types.h"
#include "icemu/hooks/Hook.h"
#include "icemu/hooks/HookCode.h"
#include "icemu/hooks/HookMemory.h"
#include "icemu/hooks/Hooks.h"

namespace icemu {

class HookManager {
 private:
  Hooks<HookCode> hooks_code_;
  Hooks<HookMemory> hooks_memory_;

  // Used for easy cleanup
  std::set<Hook *> hooks_all;
  inline void track_hook(Hook *h) { hooks_all.insert(h); }

 public:
  typedef std::function<void(HookManager &hb)> ExtensionHookFn;

  HookManager() = default;

  ~HookManager() {
    for (auto h : hooks_all) {
      //std::cout << "Deleting: " << h->name << " addr: " << h << std::endl;
      delete h;
    }
  }

  void add(HookCode *hook) {
    //std::cout << "Hook Builder adding code hook: " << hook->name
    //          << " addr: " << hook << std::endl;
    track_hook(hook);
    hooks_code_.add(hook);
  }

  void add(HookMemory *hook) {
    //std::cout << "Hook Builder adding memory hook: " << hook->name
    //          << " addr: " << hook << std::endl;
    track_hook(hook);
    hooks_memory_.add(hook);
  }

  void run(armaddr_t address, HookCode::hook_arg_t *arg) {
    hooks_code_.run(address, arg);
  }

  void run(armaddr_t address, HookMemory::hook_arg_t *arg) {
    hooks_memory_.run(address, arg);
  }

  Hook *get(std::string name) {
    for (Hook *h : hooks_all) {
      if (h->name == name) {
        return h;
      }
    }
    return NULL;
  }
};
}  // namespace icemu

#endif /* ICEMU_HOOKS_HOOKMANAGER_H_ */
