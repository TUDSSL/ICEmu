#include <iostream>
#include <vector>

#include "boost/program_options.hpp"

#include "icemu/ArgParse.h"

//
// Example from boost/lib/program_options/example/options_description.cpp
//

using namespace std;
using namespace icemu;

using namespace boost;
namespace po = boost::program_options;
// A helper function to simplify the main part.
template <class T>
ostream &operator<<(ostream &os, const vector<T> &v) {
  copy(v.begin(), v.end(), ostream_iterator<T>(os, " "));
  return os;
}

bool ArgParse::parse(int argc, char **argv) {
  try {
    po::options_description desc("Allowed options");
    desc.add_options()
        ("help,h", "produce help message")
        ("elf-file,e", po::value<string>(), "elf input file")
        ("memory-region,m", po::value< vector<string> >(), "memory region: NAME:HEX_ORIGIN:SIZE e.g., RWMEM:0x10000000:384K (can be passed multiple times)")
        ("plugin,p", po::value< vector<string> >(), "load plugin (can be passed multiple times)")
        ("plugin-arg,a", po::value< vector<string> >(), "arguments accessable to the plugins");

    po::positional_options_description p;
    p.add("elf-file", -1);

    po::store(
        po::command_line_parser(argc, argv).options(desc).positional(p).run(),
        vm);

    if (vm.count("help")) {
      cout << "Usage: options_description [options] program.elf\n";
      cout << desc;
      return false;
    }

    if (!vm.count("elf-file")) {
      cout << "\nError: Missing elf program file\n\n";
      cout << "Usage: options_description [options] program.elf\n";
      cout << desc;
      return false;
    }

    if (!vm.count("memory-region")) {
      cout << "Usage: options_description [options] program.elf\n";
      cout << "\nError: Expecting at least one memory region\n\n";
      cout << desc;
      return false;
    }

    po::notify(vm);

  } catch (std::exception &e) {
    cerr << e.what() << "\n";
    return false;
  }
  return true;
}
