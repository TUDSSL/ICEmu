/**
 *  ICEmu loadable plugin (library)
 */
#include <assert.h>

#include <atomic>
#include <cstdlib>
#include <iostream>
#include <regex>

#include "CycleCounter.h"
#include "PluginArgumentParsing.h"
#include "icemu/emu/Emulator.h"
#include "icemu/emu/Function.h"
#include "icemu/hooks/HookFunction.h"
#include "icemu/hooks/HookManager.h"
#include "icemu/hooks/RegisterHook.h"

using namespace std;
using namespace icemu;
using namespace PluginArgumentParsing;

class Powertrace : public HookCode {
 private:
  CycleCounter cycleCounter;

  std::string printLeader() { return "[powertrace]"; }

  uint64_t stdev = 0;
  uint64_t on_cycles = 0;
  string powertrace_output_file;
  string powertrace_input_file;

  uint64_t last_power_off = 0;

  vector<uint64_t> ResetCycles;
  size_t ResetCyclesReadIndex = 0;

  bool use_powertrace_input_file = false;

 public:
  // Always execute
  Powertrace(Emulator &emu) : HookCode(emu, "powertrace"), cycleCounter(emu) {
    /*
     * Process the arguments
     */
    auto stdev_arg = GetArguments(emu, "powertrace-stdev");
    auto on_cycles_arg = GetArguments(emu, "powertrace-on-cycles=");
    auto powertrace_output_file_arg =
        GetArguments(emu, "powertrace-output-file=");
    auto powertrace_input_file_arg =
        GetArguments(emu, "powertrace-input-file=");

    if (stdev_arg.args.size()) stdev = std::stoi(stdev_arg.args[0]);

    if (on_cycles_arg.args.size()) on_cycles = std::stoi(on_cycles_arg.args[0]);

    if (powertrace_output_file_arg.args.size()) {
      powertrace_output_file = powertrace_output_file_arg.args[0];
      if (powertrace_output_file_arg.has_magic)
        powertrace_output_file = powertrace_output_file + ".powertrace.csv";
    }

    if (powertrace_input_file_arg.args.size()) {
      powertrace_input_file = powertrace_input_file_arg.args[0];
      if (powertrace_input_file_arg.has_magic)
        powertrace_input_file = powertrace_input_file + ".powertrace.csv";

      use_powertrace_input_file = true;
    }

    if (use_powertrace_input_file) {
      cout << printLeader()
           << " reading power-trace input from: " << powertrace_input_file
           << endl;
    } else {
      cout << printLeader()
           << " writing power-trace output to: " << powertrace_output_file
           << endl;
      cout << printLeader() << " ON cycles: " << on_cycles << std::endl;
    }

    /*
     * Prepare the powertrace
     */
    if (use_powertrace_input_file) {
      ifstream ptf;
      ptf.open(powertrace_input_file);
      if (!ptf.is_open()) {
        cout << "Could not read power trace input file: "
             << powertrace_input_file << std::endl;
        assert(false);
      }

      string line;
      while (getline(ptf, line)) {
        uint64_t c = stoi(line);
        ResetCycles.push_back(c);
      }

      ptf.close();
    }
  }

  ~Powertrace() {
    if (powertrace_output_file.size() != 0) {
      /*
       * Write the reset cycles to a csv file
       */
      cout << printLeader()
           << " writing power-trace output to: " << powertrace_output_file
           << endl;
      ofstream ptf;
      ptf.open(powertrace_output_file);
      if (ptf.is_open()) {
        for (const auto c : ResetCycles) {
          ptf << c << std::endl;
        }
      }
      ptf.close();
    }
  }

  void power_failure(uint64_t c) {
    // Trigger a power failure
    // Reset the emulator
    getEmulator().reset();

    setStatus(STATUS_SKIP_REST);

    cout << printLeader() << " EMU RESET at: " << c << std::endl;
  }

  // Hook run
  void run(hook_arg_t *arg) {
    // No powerfailures TODO: skip registering the plugin?
    if (on_cycles == 0) return;

    // Get the current cycle count
    auto c = cycleCounter.cycleCount();

    if (use_powertrace_input_file) {
      if ((ResetCyclesReadIndex < ResetCycles.size()) &&
          (c >= ResetCycles[ResetCyclesReadIndex])) {
        power_failure(c);

        last_power_off = c;
        ResetCyclesReadIndex++;
        return;
      }

    } else {
      // Power failure time?
      if (c >= (last_power_off + on_cycles)) {
        power_failure(c);

        last_power_off = c;
        ResetCycles.push_back(c);
        return;
      }
    }

    // Increment the cycle count
    cycleCounter.add(arg->address, arg->size);
  }
};

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  auto mf = new Powertrace(emu);
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
