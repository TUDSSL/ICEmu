#ifndef REGISTERS_H_
#define REGISTERS_H_

#include <iomanip>
#include <iostream>

#include <unicorn/unicorn.h>

class Registers {
    public:
        enum reg{
            R0  = UC_ARM_REG_R0,  R1  = UC_ARM_REG_R1,  R2  = UC_ARM_REG_R2,  R3  = UC_ARM_REG_R3,
            R4  = UC_ARM_REG_R4,  R5  = UC_ARM_REG_R5,  R6  = UC_ARM_REG_R6,  R7  = UC_ARM_REG_R7,
            R8  = UC_ARM_REG_R8,  R9  = UC_ARM_REG_R9,  R10 = UC_ARM_REG_R10, R11 = UC_ARM_REG_R11,
            R12 = UC_ARM_REG_R12, R13 = UC_ARM_REG_R13, R14 = UC_ARM_REG_R14, R15 = UC_ARM_REG_R15,
            SP  = UC_ARM_REG_SP,  PC  = UC_ARM_REG_PC,  LR  = UC_ARM_REG_LR,
            RETURN = R0,
        };

    private:
        uc_engine *uc_ = NULL;

        const std::array<enum reg, 16> regmap= {
            R0,  R1,  R2,  R3,
            R4,  R5,  R6,  R7,
            R8,  R9,  R10, R11,
            R12, R13, R14, R15
        };

    public:
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

        inline void set(enum reg r, armaddr_t reg_val) {
            uc_reg_write(uc_, r, &reg_val);
        }

        inline void set(int reg, armaddr_t val) {
            set(regmap[reg], val);
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

#endif /* REGISTERS_H_ */
