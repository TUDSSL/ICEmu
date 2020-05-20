#ifndef SYMBOLS_H_
#define SYMBOLS_H_

#include <cstdint>
#include <map>
#include <iomanip>
#include <iostream>

typedef uint32_t armaddr_t;

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

// Printing
inline std::ostream& operator<< (std::ostream &out, const Symbols& s) {
    std::ios_base::fmtflags f(out.flags());

    for (const auto &symb : s.symbols) {
        out << " [" << std::setw(8) << std::setfill('0') << std::hex
            << symb.address << "] " << symb.name << std::endl;
    }

    out.flags(f);
    return out;
}


#endif /* SYMBOLS_H_ */
