#ifndef ICEMU_CONFIG_H_
#define ICEMU_CONFIG_H_

#include <fstream>
#include <iostream>

#include "json/json.h"

namespace Setting = Json;

class Config {
 private:
  std::string cfg_file_;
  bool good_ = false;

  bool read() {
    std::ifstream ifs(cfg_file_);

    if (ifs.fail()) {
      std::cerr << "Could not open file: " << cfg_file_ << std::endl;
      return false;
    }

    Json::CharReaderBuilder builder;
    Json::CharReader *reader = builder.newCharReader();
    std::string errs;

    if (!parseFromStream(builder, ifs, &settings, &errs)) {
      std::cerr << errs << std::endl;
      return false;
    }
    delete reader;

    return true;
  }

 public:
  Json::Value settings;

  Config(const std::string cfg_file) {
    cfg_file_ = cfg_file;
    good_ = read();
  }
  ~Config() {}

  bool good() { return good_; }
  bool bad() { return !good_; }

  void print() {
    std::cout << "Config settings:" << std::endl;
    std::cout << settings << std::endl;
  }
};

#endif /* ICEMU_CONFIG_H_ */
