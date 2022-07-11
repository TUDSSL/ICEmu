#ifndef ICEMU_EMU_SYMBOLS_H_
#define ICEMU_EMU_SYMBOLS_H_

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <list>

#include "icemu/emu/types.h"

namespace icemu {

typedef struct symbol {
  std::string name;
  address_t address;
  address_t size;

  size_t section;
  unsigned char bind;
  unsigned char type;
  unsigned char other;

  //address_t getFuncAddr() const { return address & ~0x1; }
} symbol_t;

class Symbols {
 private:
  std::map<std::string, symbol_t *> map_name_symbol;
  std::map<address_t, symbol_t *> map_addr_symbol;

  void build_maps() {
    // Build the maps if they are not already complete
    if (symbols.size() > map_name_symbol.size() ||
        symbols.size() > map_addr_symbol.size()) {
      for (symbol_t &s : symbols) {
        map_name_symbol[s.name] = &s;
        map_addr_symbol[s.address] = &s;
      }
    }
  }

 public:
  std::list<symbol_t> symbols;

  const symbol_t *get(address_t addr) {
    symbol_t *symb;

    build_maps();
    symb = map_addr_symbol.at(addr); // TODO Should I make a custom exception?
    return symb;
  }

  const symbol_t *get(std::string name) {
    symbol_t *symb;

    build_maps();
    symb = map_name_symbol.at(name); // TODO Should I make a custom exception?
    return symb;
  }

  inline void add(symbol_t symbol) { symbols.push_back(symbol); }
};

// Printing
inline std::ostream &operator<<(std::ostream &out, const Symbols &s) {
  std::ios_base::fmtflags f(out.flags());

  for (const auto &symb : s.symbols) {
    out << " [" << std::setw(8) << std::setfill('0') << std::hex << symb.address
        << "] " << symb.name << std::endl;
  }

  out.flags(f);
  return out;
}

}  // namespace icemu

#endif /* ICEMU_EMU_SYMBOLS_H_ */
