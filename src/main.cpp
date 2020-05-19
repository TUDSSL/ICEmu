#include <cstdlib>
#include <fstream>
#include <iostream>

#include "argparse.h"
#include "config.h"

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

    Setting::Value elf;
    elf["file"] = args.vm["elf-file"].as<string>();
    cfg.settings["elf"] = elf;

    cfg.print();

    //for (const auto &m : cfg.settings["memory"]) {
    //    cout << m << endl;
    //}
}
