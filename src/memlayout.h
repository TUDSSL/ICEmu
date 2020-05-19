#ifndef MEMLAYOUT_H_
#define MEMLAYOUT_H_

#include <cstdint>
#include <string>
#include <vector>
#include <list>

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

class Symbols {
    private:
        std::map<std::string, symbol_t *> map_name_symbol;
        std::map<armaddr_t, symbol_t *> map_addr_symbol;

        void build_maps() {
            // Build the maps if they are not already complete
            if (symbols.size() > map_name_symbol.size()
                    || symbols.size() > map_addr_symbol.size()) {
                for (symbol_t &s : symbols) {
                    map_name_symbol[s.name] = &s;
                    map_addr_symbol[s.address] = &s;
                }
            }
        }

    public:
        std::list<symbol_t> symbols;

        const symbol_t *get(armaddr_t addr) {
            symbol_t *symb;

            build_maps();
            try {
                symb = map_addr_symbol.at(addr);
            } catch (const std::out_of_range &e) {
                symb = NULL;
            }
            return symb;
        }

        const symbol_t *get(std::string name) {
            symbol_t *symb;

            build_maps();
            try {
                symb = map_name_symbol.at(name);
            } catch (const std::out_of_range &e) {
                symb = NULL;
            }
            return symb;
        }

        inline void add(symbol_t symbol) {
            symbols.push_back(symbol);
        }

};

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
        Symbols symbols;

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

    out << "Symbols:" << std::endl;
    for (const auto &symb : ml.symbols.symbols) {
        out << "  " << symb.name
            << " [" << std::hex << symb.address << "]"
            << std::endl;
    }

    return out;
}

#endif /* MEMLAYOUT_H_ */
