#ifndef ICEMU_EMU_EMULATOR_H_
#define ICEMU_EMU_EMULATOR_H_

#include <array>
#include <iomanip>
#include <iostream>
#include <assert.h>

#include <capstone/capstone.h>
#include <unicorn/unicorn.h>

#include "icemu/Config.h"
#include "icemu/emu/Architecture.h"
#include "icemu/emu/Memory.h"
#include "icemu/hooks/HookManager.h"
#include "icemu/plugin/PluginArguments.h"


namespace icemu {

class Emulator {
 private:
  Config &cfg_;
  Memory &mem_;

  /* The emulated architecture */
  Arch arch_;

  /* Plugin arguments */
  PluginArguments plugin_args;

  Architecture architecture;
  HookManager hook_manager;

  /* Unicorn */
  uc_engine *uc = NULL;
  /* Unicorn hooks */
  uc_hook uc_hook_code;
  uc_hook uc_hook_memory;

  /* Capstone */
  csh cs;

  bool good_ = true;

  // Register hooks in unicorn
  bool registerCodeHook();
  bool registerMemoryHook();

 public:

  Emulator(Arch arch, Config &cfg, Memory &mem) : cfg_(cfg), mem_(mem) {
    /* Set the emulator architecture */
    arch_ = arch;

    uc_err err;

    /*
     * Initialize the correct core and capstone engine
     */
    switch (arch_) {
      case EMU_ARCH_ARMV7:
        err = uc_open(UC_ARCH_ARM, (uc_mode)(UC_MODE_THUMB | UC_MODE_MCLASS), &uc);
        if (cs_open(CS_ARCH_ARM, (cs_mode)(CS_MODE_THUMB | CS_MODE_MCLASS), &cs) !=
            CS_ERR_OK) {
          std::cerr << "Failed to initialize capstone engine" << std::endl;
          good_ = false;
          assert(false);
        }
        break;

      case EMU_ARCH_RISCV32:
        err = uc_open(UC_ARCH_RISCV, (uc_mode)(UC_MODE_RISCV32), &uc);
        if (cs_open(CS_ARCH_RISCV, (cs_mode)(CS_MODE_RISCV32 | CS_MODE_RISCVC), &cs) !=
            CS_ERR_OK) {
          std::cerr << "Failed to initialize capstone engine" << std::endl;
          good_ = false;
          assert(false);
        }
        break;

      case EMU_ARCH_RISCV64:
        err = uc_open(UC_ARCH_RISCV, (uc_mode)(UC_MODE_RISCV64), &uc);
        if (cs_open(CS_ARCH_RISCV, (cs_mode)(CS_MODE_RISCV64 | CS_MODE_RISCVC), &cs) !=
            CS_ERR_OK) {
          std::cerr << "Failed to initialize capstone engine" << std::endl;
          good_ = false;
          assert(false);
        }
        break;

      default:
        std::cerr << "Unknown architecture" << std::endl;
        good_ = false;
    }

    if (err) {
      std::cerr << "Failed to create uc with error" << std::endl;
      good_ = false;
    }

    /* Initialize capstone engine */
    cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);

    /* Initialize the emulator architecture */
    architecture.init(arch_, uc);
  }

  ~Emulator() {
    uc_close(uc);
    cs_close(&cs);
  }

  bool init();
  bool run();
  void stop(std::string reason="unspecified");
  void reset();

  bool registerHooks();

  bool good() { return good_; }
  bool bad() { return !good_; }

  bool readMemory(address_t address, char *restult, address_t size);

  // Getters
  inline Arch getArch() { return arch_; }
  inline Architecture &getArchitecture() { return architecture; }
  inline Memory &getMemory() { return mem_; }
  inline HookManager &getHookManager() { return hook_manager; }
  inline Config &getConfig() { return cfg_; }
  inline uc_engine *getUnicornEngine() { return uc; }
  inline csh *getCapstoneEngine() { return &cs; }
  inline PluginArguments &getPluginArguments() { return plugin_args; };

  std::string getElfFile() { return mem_.getElfFile(); }
  std::string getElfDir();
  std::string getElfName();

};

}  // namespace icemu

#endif /* ICEMU_EMU_EMULATOR_H_ */
