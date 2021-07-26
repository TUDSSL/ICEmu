/**
 *  ICEmu loadable plugin (library)
 *
 * An example ICEmu plugin that is dynamically loaded.
 * This example prints the address of each instruction that is executed.
 *
 * Should be compiled as a shared library, i.e. using `-shared -fPIC`
 */
#include <iostream>
#include <vector>

#include "capstone/capstone.h"

#include "icemu/emu/Emulator.h"
#include "icemu/hooks/HookCode.h"
#include "icemu/hooks/HookManager.h"
#include "icemu/hooks/RegisterHook.h"

#include "CycleCounter.h"

using namespace std;
using namespace icemu;


class CycleCount : public HookCode {
 private:
  //Pipeline pipeline;
  CycleCounter cycleCounter;

  bool has_csv_output = false;
  string csv_output;

  std::string printLeader() {
    return "[cycle-count]";
  }

 public:
  // Always execute
  CycleCount(Emulator &emu) : HookCode(emu, "cycle_count"), cycleCounter(emu) {
    // Get where to store the csv
    string argument_name = "cycle-count-file=";
    for (const auto &a : getEmulator().getPluginArguments().getArgs()) {
      auto pos = a.find(argument_name);
      if (pos != string::npos) {
        auto arg_value = a.substr(pos+argument_name.length());

        csv_output = arg_value;
        if (csv_output == "%") {
          csv_output = getEmulator().getElfDir() + "/" + getEmulator().getElfName() + ".cyclecount";
        }
        has_csv_output = true;

        cout << printLeader() << " writing output to: " << csv_output << endl;
        break;
      }
    }
  }

  ~CycleCount() {
    // Optionally write the cycle count tot a file
    ofstream CycleCountFile;
    if (has_csv_output) {
      CycleCountFile.open(csv_output);
      if (!CycleCountFile.is_open()) {
        has_csv_output = false;
      }
    }

    if (has_csv_output) {
      CycleCountFile << cycleCounter.cycleCount() << endl;
    }

    cout << printLeader()
         << " the program ran for: " << cycleCounter.cycleCount()
         << " clock cycles (estimate)" << endl;

  }

  // Hook run
  void run(hook_arg_t *arg) {
    cycleCounter.add(arg->address, arg->size);
  }
};

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  HM.add(new CycleCount(emu));
}

// Class that is used by ICEmu to finf the register function
// NB.  * MUST BE NAMED "RegisterMyHook"
//      * MUST BE global
RegisterHook RegisterMyHook(registerMyCodeHook);
