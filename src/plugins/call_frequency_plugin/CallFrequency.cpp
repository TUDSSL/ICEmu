/**
 *  ICEmu loadable plugin (library)
 *
 * An example ICEmu plugin that is dynamically loaded.
 * This example prints the address of each instruction that is executed.
 *
 * Should be compiled as a shared library, i.e. using `-shared -fPIC`
 */
#include <iostream>
#include <regex>
#include <cstdlib>
#include <atomic>

#include "capstone/capstone.h"

#include "icemu/emu/Emulator.h"
#include "icemu/hooks/HookFunction.h"
#include "icemu/hooks/HookManager.h"
#include "icemu/hooks/RegisterHook.h"
#include "icemu/emu/Function.h"

#include "CycleCounter.h"

using namespace std;
using namespace icemu;

class CallFrequency : public HookCode {

 private:
  vector<string> function_names;
  vector<const symbol_t *> function_symbols;

  bool has_csv_output = false;
  string csv_output;

  CycleCounter cycleCounter;
  vector<pair<uint64_t, uint64_t>> cycles;
  uint64_t cycles_last = 0;

  std::string printLeader() {
    return "[call-frequency]";
  }

  void processCallsiteCountTrackArguments() {
    string argument_name = "call-frequency-track=";
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
  CallFrequency(Emulator &emu) : HookCode(emu, "call_frequency"), cycleCounter(emu) {
    // Get the functions to track
    processCallsiteCountTrackArguments();
    const symbol_t *func_symbol;
    for (auto f : function_names) {
      try {
        func_symbol = emu.getMemory().getSymbols().get(f);
      } catch (...) {
        cout << printLeader() << " could not find function address for: " << f
             << endl;
        continue;
      }

      cout << printLeader() << " tracking call frequency for: " << f
           << " at address: 0x" << hex << func_symbol->getFuncAddr() << dec << endl;
      function_symbols.push_back(func_symbol);
    }

    // Get where to store the csv
    string argument_name = "call-frequency-file=";
    for (const auto &a : getEmulator().getPluginArguments().getArgs()) {
      auto pos = a.find(argument_name);
      if (pos != string::npos) {
        auto arg_value = a.substr(pos+argument_name.length());

        csv_output = arg_value;
        if (csv_output == "%") {
          csv_output = getEmulator().getElfDir() + "/" + getEmulator().getElfName() + ".callfrequency.csv";
        }
        has_csv_output = true;

        cout << printLeader() << " writing output to: " << csv_output << endl;
        break;
      }
    }
  }

  armaddr_t getCallAddr(armaddr_t address) const {
    return (address & ~0x1) - 4;
  }

  ~CallFrequency() {
    ofstream CallsiteCountFile;
    if (has_csv_output) {
      CallsiteCountFile.open(csv_output);
      if (!CallsiteCountFile.is_open()) {
        has_csv_output = false;
      }
    }

    if (has_csv_output) {
      for (auto &c : cycles) {
        auto total = c.first;
        auto diff = c.second;

        CallsiteCountFile << total << "," << diff << "\n";
      }
    }
  }

  // Hook run
  void run(hook_arg_t *arg) {
    // Increase the cycle count
    cycleCounter.add(arg->address, arg->size);

    // Get the current address
    auto addr = arg->address;

    for (auto &f : function_symbols) {
      if (f->getFuncAddr() == addr) {
        // We matched one of the registered functions. Add an entry.
        // Get the current cycle count
        auto cc = cycleCounter.cycleCount();
        cycles.push_back(pair<uint64_t,uint64_t>{cc, cc-cycles_last});
        cycles_last = cc;
        break;
      }
    }
  }
};

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  auto mf = new CallFrequency(emu);
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
