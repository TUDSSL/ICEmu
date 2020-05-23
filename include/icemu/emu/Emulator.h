#ifndef ICEMU_EMU_EMULATOR_H_
#define ICEMU_EMU_EMULATOR_H_

#include <iomanip>
#include <iostream>

#include <capstone/capstone.h>
#include <unicorn/unicorn.h>

#include "icemu/Config.h"
#include "icemu/emu/Memory.h"
#include "icemu/emu/Registers.h"

namespace icemu {

class Emulator {
 private:
  Config &cfg_;
  Memory &mem_;

  /* Unicorn */
  uc_engine *uc = NULL;
  /* Capstone */
  csh cs;

  bool good_ = true;

 public:
  Registers registers;

  Emulator(Config &cfg, Memory &mem) : cfg_(cfg), mem_(mem) {
    /* Open the unicorn emulator engine */
    uc_err err =
        uc_open(UC_ARCH_ARM, (uc_mode)(UC_MODE_THUMB | UC_MODE_MCLASS), &uc);
    if (err) {
      std::cerr << "Failed to create uc with error" << std::endl;
      good_ = false;
    }

    /* Initialize capstone engine */
    if (cs_open(CS_ARCH_ARM, (cs_mode)(CS_MODE_THUMB | CS_MODE_MCLASS), &cs) !=
        CS_ERR_OK) {
      std::cerr << "Failed to initialize capstone engine" << std::endl;
      good_ = false;
    }
    cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);

    /* Initialize the emulator status */
    registers.init(uc);
  }

  ~Emulator() {
    uc_close(uc);
    cs_close(&cs);
  }

  bool init();
  bool run();

  bool good() { return good_; }
  bool bad() { return !good_; }
};

}  // namespace icemu

#endif /* ICEMU_EMU_EMULATOR_H_ */
