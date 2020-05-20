#ifndef MEMLAYOUT_H_
#define MEMLAYOUT_H_

#include <cstdint>
#include <string>
#include <vector>
#include <list>

#include "elfio/elfio.hpp"
#include "symbols.h"
#include "config.h"


typedef struct memload {
    armaddr_t origin;
    armaddr_t length;

    uint8_t *data = NULL;
} memload_t;

typedef struct memseg {
    std::string name;
    armaddr_t origin;
    armaddr_t length;

    std::vector<memload_t> memload; // Sections part of this segment

    uint8_t *data = NULL; // the content (allocated) for this segment
} memseg_t;

class MemLayout {
    private:
        bool good_ = false;
        std::string elf_file_;
        Config &cfg_;

        size_t map_segment_to_memory(armaddr_t *origin, armaddr_t *length);
        bool collect();
        bool allocate();

    public:
        ELFIO::elfio elf_reader;
        std::vector<memseg_t> memory;
        Symbols symbols;
        armaddr_t entrypoint = 0;

        MemLayout(Config &cfg, std::string elf_file) : cfg_(cfg) {
            elf_file_ = elf_file;
            good_ = collect();
            if (good_) {
                good_ = allocate();
            }
        }

        ~MemLayout() {
            // Delete the allocate data
            for (const auto &m : memory) {
                delete m.data;
                for (const auto &ml : m.memload) {
                    delete ml.data;
                }
            }
        }

        void populate();

        bool good() {return good_;}
        bool bad() {return !good_;}

        friend std::ostream& operator<< (std::ostream &out, const MemLayout& ml);
};

// Printing
inline std::ostream& operator<< (std::ostream &out, const MemLayout& ml) {
    std::ios_base::fmtflags f(out.flags());

    out << "Elf file: " << ml.elf_file_ << std::endl;
    out << "Entrypoint: 0x" << std::hex << ml.entrypoint << std::endl;
    out << "Segments:" << std::endl;

    for (const auto &m : ml.memory) {
        out << "  Name = " << m.name
            << " : Origin = 0x" << std::hex << m.origin
            << ", Length = " << std::dec << m.length << std::endl;

        for (const auto &ld : m.memload) {
            out << "    Load "
                << " orig: "
                << "0x" << std::hex << ld.origin
                << " length: "
                << ld.length
                << std::endl;
        }
    }

    //out << "Symbols:" << std::endl;
    //out << ml.symbols;

    out.flags(f);

    return out;
}

#endif /* MEMLAYOUT_H_ */
