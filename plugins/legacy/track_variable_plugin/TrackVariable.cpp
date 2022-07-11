/**
 *  ICEmu loadable plugin (library)
 *
 * An example ICEmu plugin that is dynamically loaded.
 * This example prints the address of each instruction that is executed.
 *
 * Should be compiled as a shared library, i.e. using `-shared -fPIC`
 */
#include <iostream>

#include "capstone/capstone.h"

#include "icemu/emu/Emulator.h"
#include "icemu/hooks/HookCode.h"
#include "icemu/hooks/HookManager.h"
#include "icemu/hooks/RegisterHook.h"

using namespace std;
using namespace icemu;

class HookInstructionCount : public HookCode {
 public:
  uint64_t icnt = 0;
  armaddr_t pc = 0;

  HookInstructionCount(Emulator &emu) : HookCode(emu, "icnt") {
  }

  ~HookInstructionCount() {
  }

  void run(hook_arg_t *arg) {
    pc = arg->address;
    ++icnt;
  }
};

struct DataEntry {
  armaddr_t pc;
  uint64_t reads = 0;
  uint64_t writes = 0;
};

/*
 * track-variable-file
 *  variable_name, variable_address, #_reads, #_writes, #_total
 *
 * track-data-file (per code address)
 *  code_address, variable_name, variable_address, #_reads, #_writes, #_total
 *  code_address, variable_name, variable_address, #_reads, #_writes, #_total
 *
 */
class TrackVariable : public HookMemory {
 private:

  map<string, vector<string>> ArgMap;

  vector<const symbol_t *> TrackSymbols;

  bool hasTrackFile = false;
  string TrackFileName;

  bool hasTrackDataFile = false;
  string TrackDataFileName;

  /*
   * Tracking information
   */
  typedef map<const symbol_t *, DataEntry> SymbolDataEntryMapTy;

  SymbolDataEntryMapTy SymbolDataEntryMap;
  map<const armaddr_t, SymbolDataEntryMapTy> PCSymbolDataEntryMap;

  std::string printLeader() {
    return "[track-variable]";
  }

  void processTrackVariableArgument(string argument_name) {
    for (const auto &a : getEmulator().getPluginArguments().getArgs()) {
      auto pos = a.find(argument_name);
      if (pos != string::npos) {
        auto arg_value = a.substr(pos+argument_name.length());
        ArgMap[argument_name].push_back(arg_value);
      }
    }
  }

  void processTrackVariableArguments() {
    processTrackVariableArgument("track-variable=");            // What variabe to track
    processTrackVariableArgument("track-variable-file=");       // Output summary file (otherwise stdout)
    processTrackVariableArgument("track-variable-data-file=");  // Data file (otherwise ignored)

    /*
     * Find the variable symbols to track
     */
    try {
      auto &values = ArgMap["track-variable="];
      for (auto &value : values) {
        const symbol_t *var_symbol;
        try {
          var_symbol = getEmulator().getMemory().getSymbols().get(value);
        } catch (...) {
          cout << printLeader() << " could not find symbol: " << value << endl;
          continue;
        }
        cout << printLeader() << " tracking variable " << value
             << " at address " << var_symbol->address << endl;
        TrackSymbols.push_back(var_symbol);
      }
    } catch (...) {
      cout << printLeader() << " no variables to track provided" << endl;
    }

    /*
     * Find the output file (optional)
     */
    try {
      auto &out = ArgMap["track-variable-file="];
      TrackFileName = out.at(0);
      hasTrackFile = true;
    } catch (...) {
      cout << printLeader() << " no output file provided, using stdout" << endl;
    }

    /*
     * Find the output data file (optional)
     */
    try {
      auto &out = ArgMap["track-variable-data-file="];
      TrackDataFileName = out.at(0);
      hasTrackDataFile = true;
    } catch (...) {
      cout << printLeader() << " no output data file provided." << endl;
    }
  }

  void writeTrackFile() {
    ofstream TrackFile;
    if (hasTrackFile) {
      TrackFile.open(TrackFileName);
      if (!TrackFile.is_open()) {
        hasTrackFile = false;
        cerr << printLeader() << " could not open track file: " << TrackFileName
             << " defaulting to stdout" << endl;
      } else {
        cout << printLeader() << " writing track ile to: " << TrackFileName
             << endl;
        TrackFile
            << "variable_name, variable_address(hex), reads, writes, total"
            << endl;
      }
    }
    for (auto &kv : SymbolDataEntryMap) {
      auto sym = kv.first;
      auto &data = kv.second;

      stringstream line;
      // variable_name, variable_address, #_reads, #_writes, #_total
      line << sym->name << "," << std::hex << "0x" << sym->address << std::dec
           << "," << data.reads << "," << data.writes << ","
           << data.reads + data.writes;

      if (hasTrackFile)
        TrackFile << line.str() << endl;
      else
        cout << printLeader() << "[summary] " << line.str() << endl;
    }
  }

  void writeTrackDataFile() {
    ofstream TrackDataFile;
    if (hasTrackDataFile) {
      TrackDataFile.open(TrackDataFileName);
      if (!TrackDataFile.is_open()) {
        hasTrackDataFile = false;
        cerr << printLeader()
             << " could not open track data file: " << TrackDataFileName
             << " defaulting to stdout" << endl;
      } else {
        cout << printLeader()
             << " writing track data file to: " << TrackDataFileName << endl;
        TrackDataFile
            << "code_address(hex), variable_name, variable_address(hex), reads, writes, total"
            << endl;
      }
    }
    for (auto &kv_pc : PCSymbolDataEntryMap) {
      auto pc = kv_pc.first;
      auto &sym_map = kv_pc.second;

      for (auto &kv : sym_map) {
        auto sym = kv.first;
        auto &data = kv.second;

        stringstream line;
        // code_address, variable_name, variable_address, #_reads, #_writes, #_total
        line << std::hex << "0x" << pc << "," << sym->name << ","
             << "0x" << sym->address << std::dec << "," << data.reads << ","
             << data.writes << "," << data.reads + data.writes;

        if (hasTrackDataFile)
          TrackDataFile << line.str() << endl;
        else
          cout << printLeader() << "[data] " << line.str() << endl;
      }
    }
  }

 public:
  HookInstructionCount *hook_instr_cnt;

  TrackVariable(Emulator &emu) : HookMemory(emu, "track_variable") {
    /*
     * Initialize the instruction count plugin
     * This provides the PC information
     */
    hook_instr_cnt = new HookInstructionCount(emu);

    /*
     * Collect the symbols to print the final value of when the emulation ends
     */
    processTrackVariableArguments();
  }

  ~TrackVariable() {
    /*
     * Write the optional output files
     */
    writeTrackDataFile();
    writeTrackFile();
  }

  // Hook run, should never be called
  void run(hook_arg_t *arg) {
    auto pc = hook_instr_cnt->pc;

    for (auto &sym : TrackSymbols) {
      if (sym->address == arg->address) {
        if (arg->mem_type == HookMemory::MEM_READ) {
          // Read
          SymbolDataEntryMap[sym].reads += 1;
          PCSymbolDataEntryMap[pc][sym].reads += 1;
        } else {
          // Write
          SymbolDataEntryMap[sym].writes += 1;
          PCSymbolDataEntryMap[pc][sym].writes += 1;
        }
      }
    }
  }
};

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  //HM.add(new TrackVariable(emu));
  auto mf = new TrackVariable(emu);
  if (mf->getStatus() == Hook::STATUS_ERROR) {
    delete mf->hook_instr_cnt;
    delete mf;
    return;
  }
  HM.add(mf->hook_instr_cnt);
  HM.add(mf);
}

// Class that is used by ICEmu to finf the register function
// NB.  * MUST BE NAMED "RegisterMyHook"
//      * MUST BE global
RegisterHook RegisterMyHook(registerMyCodeHook);
