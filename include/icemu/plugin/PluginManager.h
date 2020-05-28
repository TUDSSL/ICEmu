#ifndef ICEMU_PLUGIN_PLUGINMANAGER_H_
#define ICEMU_PLUGIN_PLUGINMANAGER_H_

#include <boost/dll/shared_library.hpp>
#include <iostream>
#include <exception>

#include "boost/dll.hpp"

#include "icemu/Config.h"
#include "icemu/hooks/RegisterHook.h"

namespace icemu {

class PluginManager {
 private:
  std::list<RegisterHook *> plugins;
  std::list<boost::dll::shared_library *> libraries;

 public:
  bool add(std::string libloc) {
    bool success;
    try {
      boost::dll::shared_library *lib = new boost::dll::shared_library(libloc);
      libraries.push_back(lib);
      RegisterHook *rh = &lib->get<RegisterHook>("RegisterMyHook");
      plugins.push_back(rh);
      success = true;
    } catch (std::exception &e) {
      std::cerr << "Failed loading register hook from:" << libloc << std::endl;
      std::cerr << "Error code: " << e.what() << std::endl;
      std::cerr << "Is the file name correct and is 'RegsiterMyHook' defined?"
                << std::endl;
      success = false;
    }
    return success;
  }

  std::list<RegisterHook *>& getHooks() {
    return plugins;
  }

  void registerHooks(Emulator &emu, HookManager &hm) {
    for (auto &p : plugins) {
      p->reg(emu, hm);
    }
  }

  ~PluginManager() {
    for (auto *lib : libraries) {
      delete lib;
    }
  }
};

}

#endif /* ICEMU_PLUGIN_PLUGINMANAGER_H_ */
