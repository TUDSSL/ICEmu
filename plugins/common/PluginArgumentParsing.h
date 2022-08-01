#ifndef ICEMU_PLUGINS_PLUGIN_ARGUMENTS_H_
#define ICEMU_PLUGINS_PLUGIN_ARGUMENTS_H_
/*
 *  Special patterns are expanded when parsing the argument. e.g.,
 *   - %p = path of the ELF file that is executed (including the .elf)
 *   - %d = directory of the ELF file that is executed
 *   - %f = the file name of the ELF that is executed
 *   - %b = the basename of the ELF that is executed
 */

#include <icemu/emu/types.h>
#include <cstddef>
#include <iostream>
#include <vector>
#include <regex>

#include "icemu/emu/Emulator.h"

class PluginArgumentParsing {
 public:
  typedef std::vector<std::string> arg_t;
  
  static arg_t GetArguments(icemu::Emulator &emu, std::string argument) {
    std::vector<std::string> argvals;
  
    for (const auto &a : emu.getPluginArguments().getArgs()) {
      auto pos = a.find(argument);
      if (pos != std::string::npos) {
        auto arg_string = a.substr(pos + argument.length());

        std::string p = emu.getElfFile();
        std::string d = emu.getElfDir();
        std::string f = emu.getElfName();
        std::string b = emu.getElfBaseName();
  
        // Replace all magic sequences
        arg_string = std::regex_replace(arg_string, std::regex("\%p"), p);
        arg_string = std::regex_replace(arg_string, std::regex("\%d"), d);
        arg_string = std::regex_replace(arg_string, std::regex("\%f"), f);
        arg_string = std::regex_replace(arg_string, std::regex("\%b"), b);
  
        // Add the argument to the list
        argvals.push_back(arg_string);
      }
    }
  
    return argvals;
  }
};

#endif /* ICEMU_PLUGINS_PLUGIN_ARGUMENTS_H_ */
