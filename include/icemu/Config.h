#pragma once

#include <assert.h>

#include <exception>
#include <fstream>
#include <iostream>
#include <vector>
#include <sstream>

#include "icemu/ArgParse.h"
#include "icemu/emu/types.h"

namespace icemu {

class Config {
 public:
  struct MemoryRegion {
    std::string name;
    address_t origin;
    address_t length;
  };

 private:
  std::string elf_file;
  std::vector<MemoryRegion> memory_regions;

  address_t length_string_to_numb(std::string len_str) {
    size_t suffix_idx;
    address_t len;
  
    len = stol(len_str, &suffix_idx, 10);  // TODO: is this always base 10?
  
    // Parse the suffix, i.e. K or M
    std::string suffix = len_str.substr(suffix_idx);
    if (suffix.length()) {
      // There is a suffix
      if (suffix.compare("K") == 0) {
        len *= 1024;
      } else if (suffix.compare("M") == 0) {
        len *= (1000 * 1024);
      } else {
        std::cerr << "Unknown suffix in length: " << len_str << std::endl;
        return 0;
      }
    }
    return len;
  }

 public:
    //memseg.name = mr.name;
    //memseg.origin = stol(mr.origin, nullptr, 16);
    //memseg.length = length_string_to_numb(mr.length);
  Config(ArgParse &args) {
    // Store the elf file
    elf_file = args.vm["elf-file"].as<std::string>();

    // Store the memory regions
    std::vector<std::string> region_args =
        args.vm["memory-region"].as<std::vector<std::string> >();
    for (const auto &region : region_args) {
      // Tokenize the string and parse it
      // Format: NAME:ORIGIN:LENGTH
      std::stringstream ss(region);
      std::string r_name;
      std::string r_origin;
      std::string r_length;

      auto has_error = [&]() -> bool {
        if (!ss.good()) {
          std::cerr << "Error parsing memory region argument: " << region << std::endl;
          return true;
        }
        return false;
      };

      // Get the substrings
      if (has_error()) continue;
      getline(ss, r_name, ':');

      if (has_error()) continue;
      getline(ss, r_origin, ':');

      if (has_error()) continue;
      getline(ss, r_length, ':');

      // Parse the substrings
      address_t origin = stol(r_origin, nullptr, 16);
      address_t length = length_string_to_numb(r_length);

      // Add the region
      memory_regions.push_back(MemoryRegion{.name=r_name, .origin=origin, .length=length});
    }
  }

  ~Config() {}

  std::vector<MemoryRegion> &getMemoryRegions() { return memory_regions; }

  void print() { std::cout << "Config settings:" << std::endl; }
};

}  // namespace icemu
