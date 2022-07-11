#ifndef ICEMU_PLUGINS_PLUGIN_ARGUMENTS_H_
#define ICEMU_PLUGINS_PLUGIN_ARGUMENTS_H_

#include <icemu/emu/types.h>
#include <cstddef>
#include <iostream>
#include <vector>

#include "icemu/emu/Emulator.h"

namespace PluginArgumentParsing {

//typedef std::pair<std::vector<std::string>, bool> arg_t;

struct arg_t {
  std::vector<std::string> args;
  bool has_magic;
};

inline arg_t GetArguments(icemu::Emulator &emu,
                                             std::string argument,
                                             bool magic = true) {
  std::vector<std::string> argvals;
  bool has_magic = false;

  for (const auto &a : emu.getPluginArguments().getArgs()) {
    auto pos = a.find(argument);
    if (pos != std::string::npos) {
      auto arg_value = a.substr(pos + argument.length());

      // Check for magic characters
      if (magic) {
        // '%' changes the name to <elf_path>
        if (arg_value == "%") {
          arg_value = emu.getElfDir() + "/" + emu.getElfName();
          has_magic = true;
        }
      }

      // Add the argument to the list
      argvals.push_back(arg_value);
    }
  }

  return arg_t{argvals, has_magic};
}
}  // namespace PluginArgumentParsing

#endif /* ICEMU_PLUGINS_PLUGIN_ARGUMENTS_H_ */
