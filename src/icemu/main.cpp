#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <vector>

#include "icemu/emu/types.h"
#include "icemu/ArgParse.h"
#include "icemu/Config.h"
#include "icemu/MemoryDump.h"
#include "icemu/emu/Emulator.h"
#include "icemu/emu/Memory.h"
#include "icemu/util/ElapsedTime.h"

#include "icemu/hooks/builtin/BuiltinHooks.h"

#include "icemu/plugin/PluginManager.h"

using namespace std;
using namespace icemu;

int main(int argc, char **argv) {
  ElapsedTime runtime;

  cout << "ICEmu ARM Emulator" << endl;
  ArgParse args(argc, argv);
  if (args.bad()) {
    return EXIT_FAILURE;
  }

  Config cfg(args.vm["config-file"].as<string>());

  if (cfg.bad()) {
    return EXIT_FAILURE;
  }

  Memory mem(cfg, args.vm["elf-file"].as<string>());
  if (mem.bad()) {
    cerr << "Error building memory layout" << endl;
    return EXIT_FAILURE;
  }

  cout << mem << endl;

  // Populate the allocated memory
  // i.e. load the flash to the allocated segment
  mem.populate();

  /* Run emulation */
  Emulator emu(cfg, mem);
  emu.init();

  /* Register all builtin hooks */
  BuiltinHooks::registerHooks(emu.getHookManager());

  /* Register the hooks passed as arguments */
  // Get the plugin files from the arguments
  PluginManager plugin_manager;
  if (args.vm.count("plugin")) {
    auto plugins = args.vm["plugin"].as< vector<string> >();
    for (const auto &p : plugins) {
      cout << "Loading plugin: " << p << endl;
      plugin_manager.add(p);
    }
  }
  // Actually register the hooks in the HookManager of the emulator
  plugin_manager.registerHooks(emu.getHookManager());

  cout << "Starting emulation" << endl;
  runtime.start();  // Start tracking the runtime
  emu.run();

  // Stop the time measurement
  runtime.stop();

  cout << "Emulation ended" << endl;
  cout << "Result register: " << emu.getRegisters().get(Registers::RETURN) << endl;

  // Get the runtime of the emulation
  auto s = runtime.get_s();
  cout << "Emulation time: " << s << "s" << endl;

  // Dump the registers if required
  if (args.vm.count("dump-reg")) {
    string filename = args.vm["dump-prefix"].as<string>() + "reg.txt";
    cout << "Dumping Registers to file: " << filename << endl;
    ofstream outfile;
    outfile.open(filename, ios::out | ios::trunc);
    emu.getRegisters().dump(outfile);
    outfile.close();
  }

  // Dump the memory if required
  if (args.vm.count("dump-bin")) {
    string dump_prefix = args.vm["dump-prefix"].as<string>();
    MemoryDump::dump(emu.getMemory(), dump_prefix, MemoryDump::BIN);
  }
  if (args.vm.count("dump-hex")) {
    string dump_prefix = args.vm["dump-prefix"].as<string>();
    MemoryDump::dump(emu.getMemory(), dump_prefix, MemoryDump::HEX);
  }
}
