#include <cstdlib>
#include <fstream>
#include <iostream>
#include <chrono>

#include "argparse.h"
#include "config.h"
#include "memlayout.h"
#include "memdump.h"
#include "emulator.h"

#include "elapsedtime.h"

using namespace std;

int main(int argc, char **argv)
{
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

    MemLayout mem(cfg, args.vm["elf-file"].as<string>());
    if (mem.bad()) {
        cerr << "Error building memory layout" << endl;
        return EXIT_FAILURE;
    }

    runtime.start();
    cout << mem << endl;

    // Populate the allocated memory
    // i.e. load the flash to the allocated segment
    mem.populate();

    // TODO Actual emulation xD

    // Stop the time measurement
    runtime.stop();
    auto s = runtime.get_s();
    cout << "Emulation time: " << s << "s" << endl;

    /* Post emulation */
    Emulator emu(cfg, mem);
    emu.init();
    emu.run();

    // Dump the memory if required
    if (args.vm.count("dump-bin")) {
        string dump_prefix = args.vm["dump-prefix"].as<string>();
        MemDump::dump(mem, dump_prefix, MemDump::BIN);
    }
    if (args.vm.count("dump-hex")) {
        string dump_prefix = args.vm["dump-prefix"].as<string>();
        MemDump::dump(mem, dump_prefix, MemDump::HEX);
    }
}
