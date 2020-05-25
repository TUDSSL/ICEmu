#ifndef ICEMU_HOOKS_HOOKS_H_
#define ICEMU_HOOKS_HOOKS_H_

#include <set>
#include <list>
#include <iostream>
#include <boost/icl/interval_map.hpp>

#include "icemu/emu/types.h"
#include "icemu/hooks/Hook.h"

namespace icemu {

template <class C>
class Hooks {
 private:
  typedef boost::icl::interval<armaddr_t> hookinterval_t;
  typedef std::set<Hook *> hookset_t;
  typedef boost::icl::interval_map<armaddr_t, hookset_t> interval_hookset_t;

  // Interval based hooks
  interval_hookset_t hooks_interval;

  // Hooks that run every time
  std::list<Hook *> hooks_all;

 public:
  void add(Hook *hook) {
    if (hook->type == Hook::ALL) {
      hooks_all.push_back(hook);

    } else if (hook->type == Hook::RANGE) {
      hooks_interval.add(make_pair(hookinterval_t::closed(hook->low, hook->high),
                                   hookset_t{hook}));
    } else {
      std::cerr << "Unknown hook type: " << hook->type << std::endl;
    }
  }

  template <typename T>
  void run(armaddr_t address, T *arg) {
    // Run the hooks that always run
    for (const auto *h : hooks_all) {
      ((C *)h)->run(arg);
    }

    // Run the range based hooks
    for (const auto &h : hooks_interval(address)) {
      ((C *)h)->run(arg);
    }
  }
};
}  // namespace icemu

#endif /* ICEMU_HOOKS_HOOKS_H_ */
