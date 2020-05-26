#ifndef ICEMU_CONFIG_H_
#define ICEMU_CONFIG_H_

#include <json/value.h>
#include <exception>
#include <fstream>
#include <iostream>

#include "json/json.h"

namespace icemu {

namespace Setting = Json;

class Config {
 private:
  std::string cfg_file_;
  bool good_ = false;

  bool parse(Json::Value &s, const std::string cfg_file) {
    std::ifstream ifs(cfg_file);

    if (ifs.fail()) {
      std::cerr << "Could not open file: " << cfg_file << std::endl;
      return false;
    }

    Json::CharReaderBuilder builder;
    Json::CharReader *reader = builder.newCharReader();
    std::string errs;

    if (!parseFromStream(builder, ifs, &s, &errs)) {
      std::cerr << errs << std::endl;
      return false;
    }
    delete reader;

    return true;
  }

#if 0 // TODO: Fix issue #2
  void update(Json::Value &a, Json::Value &b) {
    if (!a.isObject() || !b.isObject()) {
      return;
    }
    for (const auto &key : b.getMemberNames()) {
      if (a[key].type() == Json::objectValue &&
          b[key].type() == Json::objectValue) {
        update(a[key], b[key]);

      } else if (a[key].type() == Json::arrayValue &&
                 b[key].type() == Json::arrayValue) {
        for (const auto &entry : b[key]) {
          bool updated_entry = false;
          try {
            std::string entry_name = entry["name"].asString();
            // Find the entry name in the existing configuration
            for (auto &old_entry : a[key]) {
              if (entry_name == old_entry["name"].asString()) {
                old_entry = entry;
                updated_entry = true;
              }
            }
          } catch (...) {
          }
          if (!updated_entry) {
            a[key].append(entry);
          }
        }
      } else {
        a[key] = b[key];
      }
    }
  }
#endif

 public:
  Json::Value settings;

  Config(const std::string cfg_file) {
    cfg_file_ = cfg_file;
    good_ = parse(settings, cfg_file);
  }
  Config() = default;

  ~Config() {}

  bool good() { return good_; }
  bool bad() { return !good_; }

  bool add(const std::string cfg_file) {
    good_ = false;
    if (!settings.isObject()) {
      // First one
      cfg_file_ = cfg_file; // Set the "main" cfg file
      good_ = parse(settings, cfg_file);
    } else {
      // Merge the new config into the old one
      std::cout << "MERGING CONFIGURATION FILES SUCKS AND IS INCOMPLETE, SEE ISSUE #2" << std::endl;
      std::cout << "PLEASE DON'T USE THIS, MERGE THE CONFIGURATION MANUALLY" << std::endl;
      good_ = false;
      #if 0
      Json::Value update_settings;
      good_ = parse(update_settings, cfg_file);
      if (good_) {
        try {
          update(settings, update_settings);
        } catch (std::exception &e) {
          std::cerr << "Failed merging configuration files (merging in: " << cfg_file << ")" << std::endl;
          std::cerr << "Error: " << e.what() << std::endl;
          good_ = false;
        }
      }
      #endif
    }
    return good_;
  }

  void print() {
    std::cout << "Config settings:" << std::endl;
    std::cout << settings << std::endl;
  }
};

}  // namespace icemu

#endif /* ICEMU_CONFIG_H_ */
