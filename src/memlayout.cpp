#include <iostream>
#include <cstdint>
#include <vector>
#include <cstring>

#include "elfio/elfio.hpp"

#include "memlayout.h"

using namespace ELFIO;
using namespace std;

static armaddr_t length_string_to_numb(string len_str)
{
    size_t suffix_idx;
    armaddr_t len;

    len = stoi(len_str, &suffix_idx, 10); // TODO: is this always base 10?

    // Parse the suffix, i.e. K or M
    string suffix = len_str.substr(suffix_idx);
    if (suffix.length()) {
        // There is a suffix
        if (suffix.compare("K") == 0) {
            len *= 1024;
        } else if (suffix.compare("M") == 0) {
            len *= (1000*1024);
        } else {
            cerr << "Unknown suffix in length: " << len_str << endl;
            return 0;
        }
    }

    return len;
}

size_t MemLayout::map_segment_to_memory(armaddr_t *origin, armaddr_t *length)
{
    armaddr_t low, high;
    bool has_changed = 0;

    low = *origin;
    high = *origin + *length;

    int i;
    for (i=0; i<memory.size(); i++) {

        auto &m = memory.at(i);

        armaddr_t m_low = m.origin;
        armaddr_t m_high = m.origin+m.length;

        if ((low >= m_low && low <= m_high) || high >= m_low && high <= m_high) {
            // One of the points is in the memory range.
            // Cut off stuff thats outside
            if (low < m_low) {
                low = m_low;
            }

            if (high > m_high) {
                high = m_high;
            }

            *origin = low;
            *length = high-low;
            return i;
        }
    }
    return i;
}

/*
 * Collect the sections and init fields from the elf file
 * and the config
 * TODO: Add error handling for the JSON reader??
 */
bool MemLayout::collect()
{
    /* Get the memory sections from the config */
    for (const auto &m : cfg_.settings["memory"]) {
        memseg_t memseg;
        memseg.name = m["name"].as<string>();
        memseg.origin = stoi(m["origin"].as<string>(), nullptr, 16);
        memseg.length = length_string_to_numb(m["length"].as<string>());

        memory.push_back(memseg);
    }

    /* Get the corresponding memory segments to fill/load from the elf file */
    if (!elf_reader.load(elf_file_)) {
        cerr << "Error reading elf file" << elf_file_ << endl;
        return false;
    }

    size_t seg_num = elf_reader.segments.size();
    for (int i=0; i<seg_num; i++) {
        const segment *pseg = elf_reader.segments[i];

        armaddr_t seg_origin = pseg->get_physical_address();
        armaddr_t seg_length = pseg->get_file_size();

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
            armaddr_t offset = seg_origin - pseg->get_physical_address();

            // Copy the data
            memcpy(mload.data, &pseg->get_data()[offset], mload.length);

            // Push the mload to the correct memory entry
            memory.at(mem_idx).memload.push_back(mload);
        }
    }

    // Build a map for the symbols (aka the symbol table)
    size_t sec_num = elf_reader.sections.size();
    for (int i=0; i<sec_num; i++) {
        section *psec = elf_reader.sections[i];
        if (psec->get_type() == SHT_SYMTAB || psec->get_type() == SHT_DYNSYM) {
            symbol_section_accessor symbls(elf_reader, psec);

            size_t sym_num = symbls.get_symbols_num();
            for (int j=0; j<sym_num; j++) {
                std::string   name;
                Elf64_Addr    value   = 0;
                Elf_Xword     size    = 0;
                unsigned char bind    = 0;
                unsigned char type    = 0;
                Elf_Half      section = 0;
                unsigned char other   = 0;
                symbls.get_symbol(j, name, value, size, bind, type, section, other );

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

bool MemLayout::allocate()
{
    try {
        for (auto &m : memory) {
            if (m.data != NULL) {
                cerr << "Memory segment already allocated" << endl;
                return false;
            }
            m.data = new uint8_t[m.length];
        }
    } catch (const std::bad_alloc &) {
        return false;
    }
    return true;
}

void MemLayout::populate()
{
    for (auto &m : memory) {
        uint8_t *data = m.data;
        for (const auto &ml : m.memload) {
            size_t start_wr = ml.origin - m.origin;
            memcpy(&data[start_wr], ml.data, ml.length);
        }
    }
}
