#ifndef EMULATOR_H_
#define EMULATOR_H_

#include "config.h"
#include "memlayout.h"

class Emulator {

    Config &cfg_;
    MemLayout &mem_;

    public:
        Emulator(Config &cfg, MemLayout &mem) : cfg_(cfg), mem_(mem) {}

        bool init();
        bool run();
};

#endif /* EMULATOR_H_ */
