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

class InstructionProfiling : public HookCode {

 private:
  bool has_csv_output = false;
  string csv_output;

  map<armaddr_t, uint64_t> InstructionCountMap;

  std::string printLeader() {
    return "[instruction-profiling]";
  }

 public:
  // Always execute
  InstructionProfiling(Emulator &emu) : HookCode(emu, "callsite_count") {
    // Get where to store the csv
    // TODO: Only load the plugin if a csv file is present
    string argument_name = "instruction-profiling-file=";
    for (const auto &a : getEmulator().getPluginArguments().getArgs()) {
      auto pos = a.find(argument_name);
      if (pos != string::npos) {
        auto arg_value = a.substr(pos+argument_name.length());

        csv_output = arg_value;
        if (csv_output == "%") {
          csv_output = getEmulator().getElfDir() + "/" + getEmulator().getElfName() + ".instructionprofiling.csv";
        }
        has_csv_output = true;

        cout << printLeader() << " writing output to: " << csv_output << endl;
        break;
      }
    }
  }

  ~InstructionProfiling() {
    // Open the CSV file if it exists
    ofstream InstructionProfilingFile;
    if (has_csv_output) {
      InstructionProfilingFile.open(csv_output);
      if (!InstructionProfilingFile.is_open()) {
        has_csv_output = false;
      }
    }

    // Do nothing wihtout a CSV
    if (has_csv_output) {
      for (const auto &kv : InstructionCountMap) {
        InstructionProfilingFile << hex << "0x" << kv.first << dec << ","
                                 << kv.second << endl;
      }
    } else {
      cout << printLeader() << " no .csv file provided or can't open it" << endl;
    }
  }

  // Hook run
  void run(hook_arg_t *arg) {
    auto addr = arg->address;
    // Increment the instruction count
    InstructionCountMap[addr]++;
  }
};

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  auto mf = new InstructionProfiling(emu);
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
