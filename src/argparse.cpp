#include <iostream>
#include "boost/program_options.hpp"

#include "argparse.h"

//
// Example from boost/lib/program_options/example/options_description.cpp
//

using namespace std;

using namespace boost;
namespace po = boost::program_options;
// A helper function to simplify the main part.
template<class T>
ostream& operator<<(ostream& os, const vector<T>& v)
{
    copy(v.begin(), v.end(), ostream_iterator<T>(os, " "));
    return os;
}

bool ArgParse::parse(int argc, char **argv)
{
    try {
        po::options_description desc("Allowed options");
        desc.add_options()
            ("help", "produce help message")
            ("config-file,c", po::value<string>()->required(), "json config file")
            ("elf-file,e", po::value<string>(), "elf input file")
        ;

        po::positional_options_description p;
        //p.add("config-file", -1);
        p.add("elf-file", -1);

        po::store(po::command_line_parser(argc, argv).
                  options(desc).positional(p).run(), vm);
        po::notify(vm);

        if (vm.count("help")) {
            cout << "Usage: options_description [options]\n";
            cout << desc;
            return false;
        }

        //if (vm.count("config-file"))
        //{
        //    cout << "config file: "
        //         << vm["config-file"].as<string>() << "\n";
        //}

        //if (vm.count("elf-file"))
        //{
        //    cout << "elf file: "
        //         << vm["elf-file"].as<string>() << "\n";
        //}
    }
    catch(std::exception& e)
    {
        cerr << e.what() << "\n";
        return false;
    }
    return true;
}
