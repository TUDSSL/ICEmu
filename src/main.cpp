#include <cstdlib>
#include <fstream>
#include <iostream>

#include "argparse.h"
#include "config.h"
#include "memlayout.h"
#include "memdump.h"

#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>

using namespace std;

int main(int argc, char **argv)
{
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

    cout << mem << endl;

    // Populate the allocated memory
    // i.e. load the flash to the allocated segment
    mem.populate();

    // TODO Actual emulation xD

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
