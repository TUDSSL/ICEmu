#ifndef ICEMU_ARGPARSE_H_
#define ICEMU_ARGPARSE_H_

#include "boost/program_options.hpp"

namespace icemu {

class ArgParse {
 private:
  bool good_ = false;
  bool parse(int argc, char **argv);

 public:
  boost::program_options::variables_map vm;

  ArgParse(int argc, char **argv) { good_ = parse(argc, argv); }

  bool good() { return good_; }
  bool bad() { return !good_; }
};

}  // namespace icemu

#endif /* ICEMU_ARGPARSE_H_ */
