#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>
#include <assert.h>

#include "elfio/elfio.hpp"

#include "icemu/emu/types.h"
#include "icemu/emu/Memory.h"

using namespace ELFIO;
using namespace std;
using namespace icemu;

size_t Memory::map_segment_to_memory(address_t *origin, address_t *length) {
  address_t low, high;
  low = *origin;
  high = *origin + *length;

  size_t i;
  for (i = 0; i < memory.size(); i++) {
    auto &m = memory.at(i);

    address_t m_low = m.origin;
    address_t m_high = m.origin + m.length;

    if (((low >= m_low) && (low <= m_high)) ||
        ((high >= m_low) && (high <= m_high))) {
      // One of the points is in the memory range.
      // Cut off stuff thats outside
      if (low < m_low) {
        low = m_low;
      }

      if (high > m_high) {
        high = m_high;
      }

      *origin = low;
      *length = high - low;
      return i;
    }
  }
  return i;
}

/*
 * Collect the sections and init fields from the elf file
 * and the config
 */
bool Memory::collect() {
  /* Get the memory sections from the config */
  for (const auto &mr : cfg_.getMemoryRegions()) {
    memseg_t memseg;
    memseg.name = mr.name;
    memseg.origin = mr.origin;
    memseg.length = mr.length;

    memory.push_back(memseg);
  }

  /* Get the corresponding memory segments to fill/load from the elf file */
  if (!elf_reader.load(elf_file_)) {
    cerr << "Error reading elf file " << elf_file_ << endl;
    return false;
  }

  /* Get the entry point */
  entrypoint = elf_reader.get_entry();

  /* Get the architecture */
  /* https://en.wikipedia.org/wiki/Executable_and_Linkable_Format */
  unsigned char e_machine = elf_reader.get_machine();
  unsigned char e_class = elf_reader.get_class();

  // ARMv7 32-bit
  if (e_machine == 0x28 && e_class == 1) {
    elf_arch = Arch::EMU_ARCH_ARMV7;
  } 
  // RISCV 32-bit
  else if (e_machine == 0xF3 && e_class == 1) {
    elf_arch = Arch::EMU_ARCH_RISCV32;
  }
  // RISCV 64-bit
  else if (e_machine == 0xF3 && e_class == 2) {
    elf_arch = Arch::EMU_ARCH_RISCV64;
  }
  // Unknown
  else {
    cerr << "ELF architecture not supported" << endl;
    cerr << "ELF class: " << (uint32_t)e_class << endl;
    cerr << "ELF machine: " << (uint32_t)e_machine << endl;
    assert(false);
  }

  size_t seg_num = elf_reader.segments.size();
  for (size_t i = 0; i < seg_num; i++) {
    const segment *pseg = elf_reader.segments[i];

    address_t seg_origin = pseg->get_physical_address();
    address_t seg_length = pseg->get_file_size();

    if (seg_length == 0) {
      continue;
    }

#if 0
        cout << "Mapping Segment: " << i
            << " Origin: "
            << seg_origin
            << " Length: "
            << seg_length
            << endl;
#endif

    // Map the segment to fit in one of the allocated memory segments
    size_t mem_idx = map_segment_to_memory(&seg_origin, &seg_length);
    if (mem_idx < memory.size()) {
      // cout << "Mapped: " << seg_origin << " len: " << seg_length << endl;

      // Now add the data to load to the memory memload vevtor
      memload_t mload;
      mload.origin = seg_origin;
      mload.length = seg_length;
      mload.data = new uint8_t[mload.length];

      // We might have skipped garbage by reducing the length, so
      // we need to calculate the offset
      address_t offset = seg_origin - pseg->get_physical_address();

      // Copy the data
      memcpy(mload.data, &pseg->get_data()[offset], mload.length);

      // Push the mload to the correct memory entry
      memory.at(mem_idx).memload.push_back(mload);
    }
  }

  // Build a map for the symbols (aka the symbol table)
  size_t sec_num = elf_reader.sections.size();
  for (size_t i = 0; i < sec_num; i++) {
    section *psec = elf_reader.sections[i];
    if (psec->get_type() == SHT_SYMTAB || psec->get_type() == SHT_DYNSYM) {
      symbol_section_accessor symbls(elf_reader, psec);

      size_t sym_num = symbls.get_symbols_num();
      for (size_t j = 0; j < sym_num; j++) {
        std::string name;
        Elf64_Addr value = 0;
        Elf_Xword size = 0;
        unsigned char bind = 0;
        unsigned char type = 0;
        Elf_Half section = 0;
        unsigned char other = 0;
        symbls.get_symbol(j, name, value, size, bind, type, section, other);

        // Only add the symbol if we can actually find it later
        // i.e. if it has a name
        if (name.length()) {
          symbol_t symb;
          symb.address = value;
          symb.size = size;
          symb.bind = bind;
          symb.type = type;
          symb.section = section;
          symb.other = other;
          symb.name = name;

          symbols.add(symb);
        }
      }
    }
  }
  return true;
}

static inline size_t align_4096(size_t length) {
  const size_t align = (1024*4);
  size_t res = ((length + align - 1) / align) * align;
  return res;
}

bool Memory::allocate() {
  try {
    for (auto &m : memory) {
      if (m.data != NULL) {
        cerr << "Memory segment already allocated" << endl;
        return false;
      }
      // For the emulator (unicorn) we need allocated memory chunks
      // to be a multiple of 4096
      m.allocated_length = align_4096((size_t)m.length);
      m.data = new uint8_t[m.allocated_length];
      memset(m.data, 0, m.allocated_length);
    }
  } catch (const std::bad_alloc &) {
    return false;
  }
  return true;
}

void Memory::populate() {
  for (auto &m : memory) {
    uint8_t *data = m.data;
    for (const auto &ml : m.memload) {
      size_t start_wr = ml.origin - m.origin;
      memcpy(&data[start_wr], ml.data, ml.length);
    }
  }
}

memseg_t *Memory::find(string memseg_name) {
  for (auto &ms : memory) {
    if (ms.name == memseg_name) {
      return &ms;
    }
  }
  return nullptr;
}

memseg_t *Memory::find(address_t address) {
  for (auto &ms : memory) {
    if (address >= ms.origin && address < (ms.origin + ms.length)) {
      return &ms;
    }
  }
  return nullptr;
}

char *Memory::at(address_t address) {
  auto mseg = find(address);
  char *data_start = (char *)&mseg->data[address - mseg->origin];
  return data_start;
}
