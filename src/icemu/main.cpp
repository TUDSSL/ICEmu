#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <vector>
#include <csignal>
#include <atomic>

#include "icemu/emu/types.h"
#include "icemu/ArgParse.h"
#include "icemu/Config.h"
#include "icemu/emu/Emulator.h"
#include "icemu/emu/Memory.h"
#include "icemu/util/ElapsedTime.h"
#include "icemu/hooks/builtin/BuiltinHooks.h"
#include "icemu/plugin/PluginManager.h"

using namespace std;
using namespace icemu;

namespace icemu {
volatile atomic<bool> gStopEmulation;
}

void main_signal_handler(int signal) {
  // A signal occured
  cout << "Captured signal: " << signal << endl;
  gStopEmulation = true;
}

int main(int argc, char **argv) {
  ElapsedTime runtime;

  /* Register the plugin based hooks */
  PluginManager plugin_manager;

  cout << "ICEmu ARM Emulator" << endl;

  // Setup signal handler
  signal(SIGINT, main_signal_handler);

  ArgParse args(argc, argv);
  if (args.bad()) {
    exit(EXIT_FAILURE);
  }

  /* Add all the configuration files in order they appeared in */
  Config cfg(args);

  Memory mem(cfg, args.vm["elf-file"].as<string>());
  if (mem.bad()) {
    cerr << "Error building memory layout" << endl;
    exit(EXIT_FAILURE);
  }

  cout << mem << endl;

  // Populate the allocated memory
  // i.e. load the flash to the allocated segment
  mem.populate();

  /* Run emulation */
  Emulator emu(mem.elf_arch, cfg, mem);
  emu.init();

  /* Add the plugin arguments */
  auto &plugin_args = emu.getPluginArguments();
  if (args.vm.count("plugin-arg")) {
    auto pargs = args.vm["plugin-arg"].as< vector<string> >();
    plugin_args.add(pargs);
  }

  /* Register all builtin hooks */
  BuiltinHooks::registerHooks(emu, emu.getHookManager());

  // Register the hooks passed as arguments
  // Get the plugin files from the arguments
  if (args.vm.count("plugin")) {
    auto plugins = args.vm["plugin"].as< vector<string> >();
    for (const auto &p : plugins) {
      cout << "Loading plugin: " << p << " (argument)" << endl;
      plugin_manager.add(p);
    }
  }
  // Actually register the hooks in the HookManager of the emulator
  plugin_manager.registerHooks(emu, emu.getHookManager());

  cout << "Starting emulation" << endl;
  runtime.start();  // Start tracking the runtime
  emu.run();

  // Stop the time measurement
  runtime.stop();

  cout << "Emulation ended" << endl;
  cout << "Result register: "
       << emu.getArchitecture().registerGet(Architecture::REG_RETURN)
       << endl;

  // Get the runtime of the emulation
  auto s = runtime.get_s();
  cout << "Emulation time: " << s << "s" << endl;

  return EXIT_SUCCESS;
}
