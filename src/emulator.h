#ifndef EMULATOR_H_
#define EMULATOR_H_

#include <iomanip>
#include <iostream>

#include "config.h"
#include "memlayout.h"

#include <unicorn/unicorn.h>
#include <capstone.h>

class RegisterStatus {
    uc_engine *uc_ = NULL;

    public:
        enum reg{
            R0  = UC_ARM_REG_R0,  R1  = UC_ARM_REG_R1,  R2  = UC_ARM_REG_R2,  R3  = UC_ARM_REG_R3,
            R4  = UC_ARM_REG_R4,  R5  = UC_ARM_REG_R5,  R6  = UC_ARM_REG_R6,  R7  = UC_ARM_REG_R7,
            R8  = UC_ARM_REG_R8,  R9  = UC_ARM_REG_R9,  R10 = UC_ARM_REG_R10, R11 = UC_ARM_REG_R11,
            R12 = UC_ARM_REG_R12, R13 = UC_ARM_REG_R13, R14 = UC_ARM_REG_R14, R15 = UC_ARM_REG_R15,
            SP  = UC_ARM_REG_SP,  PC  = UC_ARM_REG_PC,  LR  = UC_ARM_REG_LR,
            RETURN = R0,
        };

        std::array<enum reg, 16> regmap= {
            R0,  R1,  R2,  R3,
            R4,  R5,  R6,  R7,
            R8,  R9,  R10, R11,
            R12, R13, R14, R15
        };

        inline void init(uc_engine *uc) {
            uc_ = uc;
        }

        inline armaddr_t get(enum reg r) {
            armaddr_t reg_val;
            uc_reg_read(uc_, r, &reg_val);
            return reg_val;
        }

        inline armaddr_t get(int reg) {
            return get(regmap[reg]);
        }

        void dump(std::ostream &out = std::cout) {
            std::ios_base::fmtflags fm(out.flags());
            const size_t w = 8;

            for (int i=0; i<regmap.size(); i++) {
                armaddr_t r;
                r = get(i);
                out << "R" << i << ((i<10) ? " " : "")
                    << ": [0x" << std::setw(w) << std::setfill('0') << std::hex << r << "] = "
                    << std::dec << r << " "
                    << std::endl;
            }

            out.flags(fm);
        }
};

// Holds generic information
// intructions emulated
// registers
class EmulatorStatus {
    public:
        RegisterStatus registers;

        void init(uc_engine *uc) {
            registers.init(uc);
        }
};

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
        EmulatorStatus status;

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
            status.init(uc);
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
