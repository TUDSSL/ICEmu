#ifndef ICEMU_EMU_ICEMU_ARCH_H_
#define ICEMU_EMU_ICEMU_ARCH_H_

#include <cstdint>

/*
 * Architecture base-class
 */
enum Arch {
    EMU_ARCH_ARMV7,
    EMU_ARCH_RISCV32,
    EMU_ARCH_RISCV64
};

/*
 * The address type is always 64 bit
 */
typedef uint64_t address_t;

#endif /* ICEMU_EMU_ICEMU_ARCH_H_ */
