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

    cout << mem << endl;

    // Populate the allocated memory
    // i.e. load the flash to the allocated segment
    mem.populate();

    /* Run emulation */
    Emulator emu(cfg, mem);
    emu.init();

    cout << "Starting emulation" << endl;
    runtime.start(); // Start tracking the runtime
    emu.run();

    // Stop the time measurement
    runtime.stop();

    cout << "Emulation ended" << endl;
    cout << "Result register: " << emu.registers.get(Registers::RETURN) << endl;
    //cout << "Registers:" << endl;
    //emu.registers.dump();

    // Get the runtime of the emulation
    auto s = runtime.get_s();
    cout << "Emulation time: " << s << "s" << endl;

    // Dump the registers if required
    if (args.vm.count("dump-reg")) {
        string filename = args.vm["dump-prefix"].as<string>() + "reg.txt";
        cout << "Dumping Registers to file: " << filename << endl;
        ofstream outfile;
        outfile.open(filename, ios::out | ios::trunc);
        emu.registers.dump(outfile);
        outfile.close();
    }

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
