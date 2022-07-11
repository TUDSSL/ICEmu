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
  string powertrace_stats_file;
  uint64_t powertrace_freq = 0;

  uint64_t last_power_off = 0;
  uint64_t reset_count = 0;

  vector<uint64_t> ResetCycles;
  size_t ResetCyclesReadIndex = 0;

  bool use_powertrace_input_file = false;

  // Wait untill main before we start applying the powertrace
  bool bootstrap = true;
  const symbol_t *main_symbol;

  // Used for looping the trace file
  uint64_t tracefile_offset = 0;

  /*
   * Convert a tick from a powertrace file to a clock tick
   * if the powertrace_freq is not set (or 0) the numbers in the powertrace
   * file map directly to clock cycles. Otherwise they are interpreted as
   * ms and converted to clock cycles using the provided freq of the processor
   */
  uint64_t tick2clock(uint64_t t) {
    if (powertrace_freq == 0) return t;
    // Convert ms to clock cycles
    uint64_t c = t*((double)powertrace_freq/1000.0);
    cout << "Converted " << t << "ms to " << c << " cycles" << endl;

    return c;
  }

 public:
  // Always execute
  Powertrace(Emulator &emu) : HookCode(emu, "powertrace"), cycleCounter(emu) {
    /*
     * Process the arguments
     */
    auto stdev_arg = GetArguments(emu, "powertrace-stdev=");
    auto on_cycles_arg = GetArguments(emu, "powertrace-on-cycles=");
    auto powertrace_output_file_arg =
        GetArguments(emu, "powertrace-output-file=");
    auto powertrace_input_file_arg =
        GetArguments(emu, "powertrace-input-file=");
    auto powertrace_stats_file_arg =
        GetArguments(emu, "powertrace-stats-file=");
    auto powertrace_freq_arg =
        GetArguments(emu, "powertrace-freq=");

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

    if (powertrace_stats_file_arg.args.size()) {
      powertrace_stats_file = powertrace_stats_file_arg.args[0];
      if (powertrace_stats_file_arg.has_magic)
        powertrace_stats_file = powertrace_stats_file + ".powertrace-stats.csv";
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

    // If the frequency arg is set, we assume that the file contains time
    // in miliseconds (ms) not clock cycles
    if (powertrace_freq_arg.args.size()) {
      powertrace_freq = std::stoi(powertrace_freq_arg.args[0]);
    }

    // Find the main symbol for bootstrapping
    try {
      main_symbol = emu.getMemory().getSymbols().get("main");
    } catch (...) {
      cout << printLeader() << " could not find the main function"
           << endl;
      bootstrap = false;
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
        ResetCycles.push_back(tick2clock(c));
      }

      ptf.close();
    }
  }

  ~Powertrace() {
    /*
     * Write the power-trace stats (APPEND!)
     *  on_cycles_mean, on_cycles_stdev, cycles, reset_count
     *
     *  on_cycles_mean = -1 when an input file is used
     *  on_cycles_mean = 0 when no power failures occur
     */
    if (powertrace_stats_file.size() != 0) {
      ofstream ptsf;
      ptsf.open(powertrace_stats_file, ios_base::app);
      if (!ptsf.is_open()) {
        cout << printLeader() << " could not write to power-trace stats file: " << powertrace_stats_file << endl;
      } else {
        cout << printLeader() << " writing power-trace stats to: " << powertrace_stats_file << endl;

        // Write the stats
        if (use_powertrace_input_file) {
          ptsf << powertrace_input_file << ",";
        } else {
          ptsf << on_cycles << ",";
        }
        ptsf << stdev << ","
          << cycleCounter.cycleCount() << ","
          << reset_count
          << endl;

        ptsf.close();
      }
    }

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

    if (use_powertrace_input_file) {
      cout << printLeader() << " used input powertrace from file: " << powertrace_input_file << endl;
    } else {
      cout << printLeader() << " ON-cycles: " << on_cycles << endl;
      cout << printLeader() << " ON-cycles stdev: " << stdev << endl;
    }
    cout << printLeader() << " total cycle count: " << cycleCounter.cycleCount() << endl;
    cout << printLeader() << " total reset count: " << reset_count << endl;
  }

  void power_failure(uint64_t c) {
    // Trigger a power failure
    // Reset the emulator
    getEmulator().reset();
    reset_count++;
    cout << printLeader() << " Power failure at: " << c << std::endl;

    setStatus(STATUS_SKIP_REST);
  }

  // Hook run
  void run(hook_arg_t *arg) {
    if (on_cycles > 0 || use_powertrace_input_file) {

      setStatus(STATUS_OK);

      // Get the current cycle count
      auto c = cycleCounter.cycleCount();

      // Power trace file
      if (use_powertrace_input_file) {
        if (bootstrap) {
          if (arg->address == main_symbol->getFuncAddr()) {
            // Start the actual powertrace
            bootstrap = false;
            last_power_off = c;
            tracefile_offset = c;
            cout << printLeader() << " Finished bootstrap at: " << c << std::endl;
          }
        } else if ((ResetCyclesReadIndex < ResetCycles.size()) &&
            (c >= (ResetCycles[ResetCyclesReadIndex]+tracefile_offset))) {
          power_failure(c);

          last_power_off = c;
          ResetCyclesReadIndex++;

          // Loop the trace file
          if (ResetCyclesReadIndex == ResetCycles.size()) {
            cout << printLeader() << " Looping trace file" << endl;
            ResetCyclesReadIndex = 0;
            tracefile_offset += ResetCycles[ResetCycles.size()-1];
          }

          return;
        }

      // Power trace generation
      } else {
        if (bootstrap) {
          if (arg->address == main_symbol->getFuncAddr()) {
            // Start the actual powertrace
            bootstrap = false;
            last_power_off = c;
            cout << printLeader() << " Finished bootstrap at: " << c << std::endl;
          }
        }
        // Power failure time?
        else if (c >= (last_power_off + on_cycles)) {
          power_failure(c);

          last_power_off = c;
          ResetCycles.push_back(c);
          return;
        }
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
