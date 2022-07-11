/**
 *  ICEmu loadable plugin (library)
 */
#include <iostream>
#include <regex>
#include <cstdlib>
#include <atomic>

#include "icemu/emu/Emulator.h"
#include "icemu/hooks/HookFunction.h"
#include "icemu/hooks/HookManager.h"
#include "icemu/hooks/RegisterHook.h"
#include "icemu/emu/Function.h"


using namespace std;
using namespace icemu;

class CallCount : public HookCode {

 private:
  vector<string> function_names;
  vector<const symbol_t *> function_symbols;

  bool has_csv_output = false;
  string csv_output;

  map<const symbol_t *, uint64_t> AddressCountMap;

  std::string printLeader() {
    return "[call-count]";
  }

  void processCallCountTrackArguments() {
    string argument_name = "call-count-track=";
    for (const auto &a : getEmulator().getPluginArguments().getArgs()) {
      auto pos = a.find(argument_name);
      if (pos != string::npos) {
        auto arg_value = a.substr(pos+argument_name.length());
        function_names.push_back(arg_value);
      }
    }
  }

 public:
  // Always execute
  CallCount(Emulator &emu) : HookCode(emu, "call_count") {
    // Get the functions to track
    processCallCountTrackArguments();
    const symbol_t *func_symbol;
    for (auto f : function_names) {
      try {
        func_symbol = emu.getMemory().getSymbols().get(f);
      } catch (...) {
        cout << printLeader() << " could not find function address for: " << f
             << endl;
        continue;
      }

      cout << printLeader() << " tracking call count for: " << f
           << " at address: 0x" << hex << func_symbol->getFuncAddr() << dec << endl;
      function_symbols.push_back(func_symbol);
    }

    // Get where to store the csv
    string argument_name = "call-count-file=";
    for (const auto &a : getEmulator().getPluginArguments().getArgs()) {
      auto pos = a.find(argument_name);
      if (pos != string::npos) {
        auto arg_value = a.substr(pos+argument_name.length());

        csv_output = arg_value;
        if (csv_output == "%") {
          csv_output = getEmulator().getElfDir() + "/" + getEmulator().getElfName() + ".callcount.csv";
        }
        has_csv_output = true;

        cout << printLeader() << " writing output to: " << csv_output << endl;
        break;
      }
    }
  }

  ~CallCount() {
    ofstream CallCountFile;
    if (has_csv_output) {
      CallCountFile.open(csv_output);
      if (!CallCountFile.is_open()) {
        has_csv_output = false;
      }
    }

    uint64_t total = 0;
    for (auto &p : AddressCountMap) {
      auto sym = p.first;
      auto cnt = p.second;
      total += cnt;

      if (has_csv_output) {
        CallCountFile << sym->name << "," << cnt << "\n";
      }

      cout << printLeader() << sym->name << ' ' << cnt
           << endl;
    }

    cout << printLeader() << " TOTAL: " << total << endl;
  }

  // Hook run
  void run(hook_arg_t *arg) {
    auto addr = arg->address;

    for (auto &f : function_symbols) {
      if (f->getFuncAddr() == addr) {
        AddressCountMap[f]++;
      }
    }
  }
};

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  auto mf = new CallCount(emu);
  if (mf->getStatus() == Hook::STATUS_ERROR) {
    delete mf;
    return;
  }
  HM.add(mf);
}

// Class that is used by ICEmu to finf the register function
// NB.  * MUST BE NAMED "RegisterMyHook"
//      * MUST BE global
RegisterHook RegisterMyHook(registerMyCodeHook);
