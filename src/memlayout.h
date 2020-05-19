#ifndef MEMLAYOUT_H_
#define MEMLAYOUT_H_

#include <cstdint>
#include <string>
#include <vector>

#include "elfio/elfio.hpp"
#include "config.h"

typedef uint32_t armaddr_t;

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
} memseg_t;

typedef struct symbol {
    std::string name;
    armaddr_t address;
    armaddr_t size;

    size_t section;
    unsigned char bind;
    unsigned char type;
    unsigned char other;
} symbol_t;

class MemLayout {
    private:
        bool good_ = false;
        std::string elf_file_;
        Config &cfg_;

        size_t map_segment_to_memory(armaddr_t *origin, armaddr_t *length);
        bool collect();

    public:
        ELFIO::elfio elf_reader;
        std::vector<memseg_t> memory;
        std::map<std::string, symbol_t> symbols;

        MemLayout(Config &cfg, std::string elf_file) : cfg_(cfg) {
            elf_file_ = elf_file;
            good_ = collect();
        }

        ~MemLayout() {
            // Delete the allocate data
            for (const auto &m : memory) {
                for (const auto &ml : m.memload) {
                    delete ml.data;
                }
            }
        }

        bool good() {return good_;}
        bool bad() {return !good_;}

        friend std::ostream& operator<< (std::ostream &out, const MemLayout& ml);
};

// Printing
inline std::ostream& operator<< (std::ostream &out, const MemLayout& ml) {
    out << "Elf file: " << ml.elf_file_ << std::endl;
    out << "Segments:" << std::endl;

    for (const auto &m : ml.memory) {
        out << "Name = " << m.name
            << " : Origin = 0x" << std::hex << m.origin
            << ", Length = " << std::dec << m.length << std::endl;

        for (const auto &ld : m.memload) {
            out << "  Load "
                << " orig: "
                << "0x" << std::hex << ld.origin
                << " length: "
                << ld.length
                << std::endl;
        }
    }

    out << "Symbols:" << std::endl;
    for (const auto &symb : ml.symbols) {
        out << "  " << symb.second.name
            << " [" << std::hex << symb.second.address << "]"
            << std::endl;
    }

    return out;
}

#endif /* MEMLAYOUT_H_ */
