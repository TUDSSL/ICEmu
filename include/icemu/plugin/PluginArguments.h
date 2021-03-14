#ifndef ICEMU_PLUGIN_PLUGINARGUMENTS_H_
#define ICEMU_PLUGIN_PLUGINARGUMENTS_H_

#include <string>
#include <vector>

namespace icemu {

class PluginArguments {
 private:
  std::list<std::string> args_;

 public:

  void add(std::string arg) {
    args_.push_back(arg);
  }

  void add(std::vector<std::string> args) {
    for (const auto &a : args) {
      add(a);
    }
  }

  const std::list<std::string>& getArgs() {
    return args_;
  }

};

}

#endif /* ICEMU_PLUGIN_PLUGINARGUMENTS_H_ */
