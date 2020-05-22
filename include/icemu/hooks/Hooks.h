#ifndef ICEMU_HOOKS_HOOKS_H_
#define ICEMU_HOOKS_HOOKS_H_

#include <set>
#include <boost/icl/interval_map.hpp>

#include "icemu/types.h"
#include "icemu/hooks/Hook.h"

template <class C>
class Hooks {
 private:
  typedef boost::icl::interval<armaddr_t> hookinterval_t;
  typedef std::set<Hook *> hookset_t;
  typedef boost::icl::interval_map<armaddr_t, hookset_t> interval_hookset_t;

  hookset_t hooks_all;
  interval_hookset_t hooks_interval;

 public:
  void add(Hook *hook) {
    hooks_interval.add(make_pair(hookinterval_t::closed(hook->low, hook->high),
                                 hookset_t{hook}));
  }

  template <typename T>
  void run(armaddr_t address, T *arg) {
    for (const auto &h : hooks_interval(address)) {
      ((C *)h)->run(arg);
    }
  }
};

#endif /* ICEMU_HOOKS_HOOKS_H_ */
