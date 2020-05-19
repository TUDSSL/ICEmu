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
 */
bool MemLayout::collect()
{
    /* Get the memory sections from the config */
    for (const auto &m : cfg_.settings["memory"]) {
        cout << "Memory: " << m["name"] << endl;

        memseg_t memseg;
        memseg.name = m["name"].as<string>();
        memseg.origin = stoi(m["origin"].as<string>(), nullptr, 16);
        memseg.length = length_string_to_numb(m["length"].as<string>());

        memory.push_back(memseg);
    }

    return true;
}
