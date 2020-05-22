#ifndef ICEMU_MEMORYDUMP_H_
#define ICEMU_MEMORYDUMP_H_

#include "icemu/emu/Memory.h"

namespace MemoryDump {

    enum dump_type {
        BIN,
        HEX,
    };

    bool dump(Memory &mem, std::string prefix = "", enum dump_type dt = HEX);
};

#endif /* ICEMU_MEMORYDUMP_H_ */
