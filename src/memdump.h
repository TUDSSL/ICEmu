#ifndef MEMDUMP_H_
#define MEMDUMP_H_

#include "memlayout.h"

namespace MemDump {

    enum dump_type {
        BIN,
        HEX,
    };

    bool dump(MemLayout &ml, std::string prefix = "", enum dump_type dt = HEX);

};

#endif /* MEMDUMP_H_ */
