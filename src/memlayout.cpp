#include <iostream>
#include <cstdint>
#include <vector>

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

    size_t sec_num = elf_reader.sections.size();
    for (int i=0; i<sec_num; i++) {
        const section *psec = elf_reader.sections[i];

        // If the address != 0 and the size != 0
        // we want to map it to memory later
        string sec_name = psec->get_name();
        armaddr_t sec_origin = psec->get_address();
        armaddr_t sec_length = psec->get_size();

        if (sec_origin > 0 && sec_length > 0) {
            // A valid section, try to map it to memory
            //cout << "Mapping Section: " << i
            //    << " Name: "
            //    << sec_name
            //    << " Origin: "
            //    << sec_origin
            //    << " Length: "
            //    << sec_length
            //    << endl;

            // TODO: Do we need to map this to memory? Or assume it always fits

            // Fit the section into a segment
            for (auto &seg : memory) {
                if (sec_origin >= seg.origin && sec_origin < (seg.origin+seg.length)) {
                    // The section fits in the segment
                    cout << "Placing section: " << sec_name
                        << " in segment: " << seg.name << endl;

                    memsec_t sec;
                    sec.name = sec_name;
                    sec.origin = sec_origin;
                    sec.length = sec_length;

                    seg.sections.push_back(sec);
                }
            }

        }

    }

    return true;
}

