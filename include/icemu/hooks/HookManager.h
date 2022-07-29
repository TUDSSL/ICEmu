#ifndef ICEMU_HOOKS_HOOKMANAGER_H_
#define ICEMU_HOOKS_HOOKMANAGER_H_

#include <list>
#include <iostream>
#include <functional>

#include "icemu/emu/types.h"
#include "icemu/hooks/Hook.h"
#include "icemu/hooks/HookCode.h"
#include "icemu/hooks/HookMemory.h"
#include "icemu/hooks/HookAllEvents.h"
#include "icemu/hooks/Hooks.h"

namespace icemu {

class HookManager {
 private:
  Hooks<HookCode> hooks_code_;
  Hooks<HookMemory> hooks_memory_;
  Hooks<HookAllEvents> hooks_all_events_;

  // Used for easy cleanup
  std::list<Hook *> hooks_all;
  inline void track_hook(Hook *h) { hooks_all.push_back(h); }

 public:
  typedef std::function<void(Emulator &emu, HookManager &hb)> ExtensionHookFn;

  HookManager() = default;

  ~HookManager() {
    for (std::list<Hook *>::reverse_iterator i = hooks_all.rbegin(); i != hooks_all.rend(); ++i) {
      //std::cout << "Deleting: " << (*i)->name << std::endl;
      delete *i;
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

  void add(HookAllEvents *hook) {
    //std::cout << "Hook Builder adding all events hook: " << hook->name
    //          << " addr: " << hook << std::endl;
    track_hook(hook);
    hooks_all_events_.add(hook);
  }

  void run(address_t address, HookCode::hook_arg_t *arg) {
    hooks_code_.run(address, arg);
  }

  void run(address_t address, HookMemory::hook_arg_t *arg) {
    hooks_memory_.run(address, arg);
  }

  void run(address_t address, HookAllEvents::hook_arg_t *arg) {
    hooks_all_events_.run(address, arg);
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
