/**
 *  ICEmu loadable plugin (library)
 *
 * Example of how to parse plugin specific arguments
 *
 * Arguments for plugins can by passed to ICEmu using '-a=<argument>'
 * Each plugin can search through all arguments provided using:
 *
 *  #include "PluginArgumentParsing.h"
 *  auto arg = PluginArgumentParsing::GetArguments(emu, "argument-name=");
 *
 *  Special patterns are expanded when parsing the argument. e.g.,
 *   - %p = path of the ELF file that is executed (including the .elf)
 *   - %d = directory of the ELF file that is executed
 *   - %f = the file name of the ELF that is executed
 *   - %b = the basename of the ELF that is executed
 *
 * Example of running the plugin:
    icemu -p build/hook_argument_plugin.so \
        -a arg-path=before/%p/after/%p \
        -a arg-dir=%d \
        -a arg-filename=%f \
        -a arg-basename=%b \
        -a arg-combo=%d/log-%b.log \
        coremark.elf
 *
 */
#include <iostream>

#include "icemu/emu/Emulator.h"
#include "icemu/hooks/HookCode.h"
#include "icemu/hooks/HookManager.h"
#include "icemu/hooks/RegisterHook.h"

#include "PluginArgumentParsing.h"

using namespace std;
using namespace icemu;

class MyHookArgumentlugin : public HookCode {
 public:
  MyHookArgumentlugin(Emulator &emu) : HookCode(emu, "Hook Argument Pluging Example") {
    // Parse the arguments

    auto arg_path = PluginArgumentParsing::GetArguments(emu, "arg-path=");
    auto arg_dir = PluginArgumentParsing::GetArguments(emu, "arg-dir=");
    auto arg_filename = PluginArgumentParsing::GetArguments(emu, "arg-filename=");
    auto arg_basename = PluginArgumentParsing::GetArguments(emu, "arg-basename=");
    auto arg_combo = PluginArgumentParsing::GetArguments(emu, "arg-combo=");

    std::cout << "Parsing arguments to hook_argument_plugin.so" << std::endl;

    if (arg_path.size()) {
      for (auto &arg : arg_path) {
        std::cout << "arg-path=" << arg << std::endl;
      }
    }

    if (arg_dir.size()) {
      for (auto &arg : arg_dir) {
        std::cout << "arg-dir=" << arg << std::endl;
      }
    }

    if (arg_filename.size()) {
      for (auto &arg : arg_filename) {
        std::cout << "arg-filename=" << arg << std::endl;
      }
    }

    if (arg_basename.size()) {
      for (auto &arg : arg_basename) {
        std::cout << "arg-basename=" << arg << std::endl;
      }
    }

    if (arg_combo.size()) {
      for (auto &arg : arg_combo) {
        std::cout << "arg-combo=" << arg << std::endl;
      }
    }

    std::cout << "Done parsing arguments to hook_argument_plugin.so" << std::endl;

  }

  // Hook run
  void run(hook_arg_t *arg) {
    (void)arg; // Don't do anything
  }
};

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  HM.add(new MyHookArgumentlugin(emu));
}

// Class that is used by ICEmu to finf the register function
// NB.  * MUST BE NAMED "RegisterMyHook"
//      * MUST BE global
RegisterHook RegisterMyHook(registerMyCodeHook);
