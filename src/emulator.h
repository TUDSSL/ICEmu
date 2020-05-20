#ifndef EMULATOR_H_
#define EMULATOR_H_

#include <iomanip>
#include <iostream>

#include "config.h"
#include "memlayout.h"
#include "registers.h"

#include <unicorn/unicorn.h>
#include <capstone.h>


class Emulator {
    private:
        Config &cfg_;
        MemLayout &mem_;

        /* Unicorn */
        uc_engine *uc = NULL;
        /* Capstone */
        csh cs;

        bool good_ = true;

    public:
        Registers registers;

        Emulator(Config &cfg, MemLayout &mem) : cfg_(cfg), mem_(mem) {
            /* Open the unicorn emulator engine */
            uc_err err = uc_open(UC_ARCH_ARM, (uc_mode)(UC_MODE_THUMB | UC_MODE_MCLASS), &uc);
            if (err) {
                std::cerr << "Failed to create uc with error" << std::endl;
                good_ = false;
            }

            /* Initialize capstone engine */
            if (cs_open(CS_ARCH_ARM, (cs_mode)(CS_MODE_THUMB | CS_MODE_MCLASS), &cs) != CS_ERR_OK) {
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

        bool good() {return good_;}
        bool bad() {return !good_;}
};

#endif /* EMULATOR_H_ */
