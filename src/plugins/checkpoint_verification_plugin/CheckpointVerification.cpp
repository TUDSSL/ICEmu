/**
 *  ICEmu loadable plugin (library)
 *
 * An example ICEmu plugin that is dynamically loaded.
 * This example prints the address of each instruction that is executed.
 *
 * Should be compiled as a shared library, i.e. using `-shared -fPIC`
 */
#include <iostream>
#include <set>

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

class ReadWriteLogger {
 public:
  typedef struct {
    set<armaddr_t> Reads;
    set<armaddr_t> Writes;
  } ReadWriteLogTy;

  struct WarReport {
    bool war;
    bool protected_war;
  };

 private:
  // The buffer for the n and n-1 index
  ReadWriteLogTy ReadWriteLogs[2];
  int n = 0;

  int otherIndex(int index) {
    if (index == 1)
      return 0;
    else
      return 1;
  }

  void clear(int index) {
    ReadWriteLogs[index].Reads.clear();
    ReadWriteLogs[index].Writes.clear();
  }

 public:
  int hasWar(set<armaddr_t> &Reads, armaddr_t Write) {
    if (Reads.find(Write) != Reads.end())
      return 1;
    else
      return 0;
  }

  set<armaddr_t>& getReads(int get_n) {
    if (get_n == -1) {
      return ReadWriteLogs[otherIndex(n)].Reads;
    }
    return ReadWriteLogs[n].Reads;
  }

  set<armaddr_t>& getWrites(int get_n) {
    if (get_n == -1) {
      return ReadWriteLogs[otherIndex(n)].Writes;
    }
    return ReadWriteLogs[n].Writes;
  }

  void checkpoint() {
    // Compute the checkpoint strength
    //auto cps = checkpointStrength();

    // Move on to the next ReadWriteLog entry
    n = otherIndex(n);
    clear(n);

    //return cps;
  }

  void addRead(armaddr_t read) {
    // Only add the read if it is not protected
    if (ReadWriteLogs[n].Writes.find(read) == ReadWriteLogs[n].Writes.end()) {
      ReadWriteLogs[n].Reads.insert(read);
    }
  }

  // Returns true if there is a WAR we missed
  WarReport addWrite(armaddr_t write) {
    ReadWriteLogs[n].Writes.insert(write);

    WarReport R;

    // If there is a WAR in the current entry we missed one! (bad)
    R.war = hasWar(ReadWriteLogs[n].Reads, write);

    // If this write was protected by the last checkpoint
    R.protected_war = hasWar(ReadWriteLogs[otherIndex(n)].Reads, write);

    return R;
  }

};

class CheckpointVerification : public HookMemory {
 private:
  map<string, vector<string>> ArgMap;

  ReadWriteLogger RWL;
  map<armaddr_t, int> PcCheckpointStrengthMap;

  set<const symbol_t *> CheckpointSymbols;
  set<armaddr_t> CheckpointAddresses;

  set<const symbol_t *> IgnoreSymbols;
  set<armaddr_t> IgnoreAddresses;

  bool hasUncaughtWarAddrFile = false;
  string UncaughtWarAddrFileName;

  bool hasUncaughtWarFile = false;
  string UncaughtWarFileName;

  bool hasCheckpointStrengthFile = false;
  string CheckpointStrengthFileName;

  typedef map<const armaddr_t, uint64_t> AddressWarMapTy;
  map<const armaddr_t, AddressWarMapTy> PcAddressWarMap;

  armaddr_t last_cp_pc = 0;

  map<const armaddr_t, uint64_t> CheckpointCountMap;

  list<string> IgnoreFunctions;
  set<armaddr_t> IgnoreFunctionAddrs;

  bool debug = false;

  const string color_start = "\033[1m\033[0;31m";
  const string color_end = "\033[0m";

  /*
   * Tracking information
   */
  std::string printLeader() {
    return "[checkpoint-verification]";
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
    processTrackVariableArgument("cpval-checkpoint-variable="); // Write to what variable indicates a checkpoint
    processTrackVariableArgument("cpval-ignore-variable="); // Write to what variable does not matter
    processTrackVariableArgument("cpval-uncaught-war-addr-file=");
    processTrackVariableArgument("cpval-uncaught-war-file=");
    processTrackVariableArgument("cpval-checkpoint-strength=");

    /*
     * Find the variable symbols to track
     */
    try {
      auto &values = ArgMap["cpval-checkpoint-variable="];
      for (auto &value : values) {
        const symbol_t *var_symbol;
        try {
          var_symbol = getEmulator().getMemory().getSymbols().get(value);
        } catch (...) {
          cout << printLeader() << " could not find symbol: " << value << endl;
          continue;
        }
        cout << printLeader() << " checkpoint variable " << value
             << " at address " << var_symbol->address << endl;
        CheckpointSymbols.insert(var_symbol);
        CheckpointAddresses.insert(var_symbol->address);
      }
    } catch (...) {
      cout << printLeader() << " no variables to track provided" << endl;
    }

    /*
     * Find the variable symbols to ignore
     */
    try {
      auto &values = ArgMap["cpval-ignore-variable="];
      for (auto &value : values) {
        const symbol_t *var_symbol;
        try {
          var_symbol = getEmulator().getMemory().getSymbols().get(value);
        } catch (...) {
          cout << printLeader() << " could not find symbol: " << value << endl;
          continue;
        }
        cout << printLeader() << " ignore variable " << value
             << " at address " << var_symbol->address << endl;
        IgnoreSymbols.insert(var_symbol);
        IgnoreAddresses.insert(var_symbol->address);
      }
    } catch (...) {
    }

    /*
     * Find the output file (optional)
     */
    try {
      auto &out = ArgMap["cpval-uncaught-war-addr-file="];
      UncaughtWarAddrFileName = out.at(0);
      hasUncaughtWarAddrFile = true;
    } catch (...) {
      cout << printLeader() << " no uncaught war address file provided, using stdout" << endl;
    }

      cout << "ELF file: " << getEmulator().getMemory().getElfFile() << endl;
    try {
      auto &out = ArgMap["cpval-uncaught-war-file="];
      UncaughtWarFileName = out.at(0);
      hasUncaughtWarFile = true;

      // Special character % indicates that we want to write to the elf dir
      if (UncaughtWarFileName == "%") {
        UncaughtWarFileName = getEmulator().getElfDir() + "/" + getEmulator().getElfName() + ".wars";
      }
    } catch (...) {
      cout << printLeader() << " no uncaught war file provided, using stdout" << endl;
    }

    /*
     * Find the output data file (optional)
     */
    try {
      auto &out = ArgMap["cpval-checkpoint-strength="];
      CheckpointStrengthFileName = out.at(0);
      hasCheckpointStrengthFile = true;
    } catch (...) {
      cout << printLeader() << " no checkpoint strenght file provided." << endl;
    }
  }

  void writeUncaughtWarAddrFile() {
    ofstream UncaughtWarAddrFile;
    if (hasUncaughtWarAddrFile) {
      UncaughtWarAddrFile.open(UncaughtWarAddrFileName);
      if (!UncaughtWarAddrFile.is_open()) {
        hasUncaughtWarAddrFile = false;
        cerr << printLeader() << " could not open file: " << UncaughtWarAddrFileName
             << " defaulting to stdout" << endl;
      } else {
        cout << printLeader() << " writing uncaught war addr file to: " << UncaughtWarAddrFileName
             << endl;
        UncaughtWarAddrFile
            << "pc(hex), memory_address(hex), war_count"
            << endl;
      }
    }

    for (auto &pc_wars : PcAddressWarMap) {
      auto &pc = pc_wars.first;
      auto &WarMap = pc_wars.second;

      for (auto &war_cnt : WarMap) {
        auto &addr = war_cnt.first;
        auto &cnt = war_cnt.second;

        stringstream line;
        // pc, memory_address, missed wars
        line << std::hex << "0x" << pc << ",0x" << addr << std::dec << "," << cnt;

        if (hasUncaughtWarAddrFile)
          UncaughtWarAddrFile << line.str() << endl;
        //else
        //  cout << color_start << printLeader() << "[uncaught-wars-addr] "
        //       << line.str() << color_end << endl;
      }
    }
  }

  void writeUncaughtWarFile() {
    ofstream UncaughtWarFile;
    if (hasUncaughtWarFile) {
      UncaughtWarFile.open(UncaughtWarFileName);
      if (!UncaughtWarFile.is_open()) {
        hasUncaughtWarFile = false;
        cerr << printLeader() << " could not open file: " << UncaughtWarFileName
             << " defaulting to stdout" << endl;
      } else {
        cout << printLeader() << " writing uncaught war file to: " << UncaughtWarFileName
             << endl;
        UncaughtWarFile
            << "pc(hex), war_count"
            << endl;
      }
    }

    uint64_t all_war_cnt = 0;
    for (auto &pc_wars : PcAddressWarMap) {
      auto &pc = pc_wars.first;
      auto &WarMap = pc_wars.second;

      uint64_t total_cnt = 0;
      for (auto &war_cnt : WarMap) {
        auto &cnt = war_cnt.second;
        total_cnt += cnt;
      }

      stringstream line;
      // pc, memory_address, missed wars
      line << std::hex << "0x" << pc << std::dec << "," << total_cnt;

      if (hasUncaughtWarFile)
        UncaughtWarFile << line.str() << endl;

      // Always print
      cout << color_start << printLeader() << "[uncaught-wars] " << line.str() << color_end << endl;

      all_war_cnt += total_cnt;
    }
    cout << color_start << printLeader() << "[total-uncaught-wars] " << all_war_cnt << color_end << endl;
  }

  void writeCheckpointStrengthFile() {
    ofstream CheckpointStrengthFile;
    if (hasCheckpointStrengthFile) {
      CheckpointStrengthFile.open(CheckpointStrengthFileName);
      if (!CheckpointStrengthFile.is_open()) {
        hasCheckpointStrengthFile = false;
        cerr << printLeader() << " could not open file: " << CheckpointStrengthFileName
             << " defaulting to stdout" << endl;
      } else {
        cout << printLeader() << " writing checkpoint strength file to: " << CheckpointStrengthFileName
             << endl;
        CheckpointStrengthFile
            << "pc(hex), strength, count"
            << endl;
      }
    }

    for (auto &kv: PcCheckpointStrengthMap) {
      auto pc = kv.first;
      auto cps = kv.second;

      stringstream line;
      // pc, strength
      line << std::hex << "0x" << pc  << std::dec << "," << cps << "," << CheckpointCountMap[pc];

      if (hasCheckpointStrengthFile)
        CheckpointStrengthFile << line.str() << endl;
      else
        cout << printLeader() << "[checkpoint-strength] " << line.str() << endl;
    }
  }

  int hasWar(set<armaddr_t> &Reads, set<armaddr_t> &Writes) {
    int wars = 0;
    for (auto &w : Writes) {
      wars += RWL.hasWar(Reads, w);
    }
    return wars;
  }

  void addCheckpointStrength(int strength) {
      if (last_cp_pc != 0)
        PcCheckpointStrengthMap[last_cp_pc] += strength;
  }

  void checkpoint(armaddr_t new_pc) {
    if (debug) cout << "CHECKPOINT" << endl;

    RWL.checkpoint();
    last_cp_pc = new_pc;
    addCheckpointStrength(0); // Init to 0
    CheckpointCountMap[new_pc] += 1;
  }

 public:
  HookInstructionCount *hook_instr_cnt;

  CheckpointVerification(Emulator &emu) : HookMemory(emu, "checkpoint_verification") {
    /*
     * Initialize the instruction count plugin
     * This provides the PC information
     */
    hook_instr_cnt = new HookInstructionCount(emu);

    /*
     * Collect the symbols to print the final value of when the emulation ends
     */
    processTrackVariableArguments();

    /*
     * Manage the ignored functions
     * TODO: merge into arguments
     */
    IgnoreFunctions.push_back("Reset_Handler");

    for (auto &IF : IgnoreFunctions) {
      const symbol_t *ifs;
      try {
        ifs = getEmulator().getMemory().getSymbols().get(IF);
        cout << printLeader() << " ignoring function " << IF
             << " at address: " << hex << ifs->getFuncAddr() << dec
             << " size: " << ifs->size << endl;

        // Add all the addresses in the function
        armaddr_t a = ifs->getFuncAddr();
        for (armaddr_t i=0; i<ifs->size; i+=2) {
          IgnoreFunctionAddrs.insert(a+i);
        }
      } catch (...) {
        cout << printLeader() << " could not find ignored function: " << IF << endl;
        continue;
      }
    }

  }

  ~CheckpointVerification() {
    /*
     * The end of the program is a checkpoint
     */

    //checkpoint(0);

    /*
     * Write the optional output files
     */
    writeCheckpointStrengthFile();
    writeUncaughtWarAddrFile();
    writeUncaughtWarFile();
  }

  // Hook run, should never be called
  void run(hook_arg_t *arg) {
    auto pc = hook_instr_cnt->pc;

    // Skip processing if it's an ignored function
    if (IgnoreFunctionAddrs.find(pc) != IgnoreFunctionAddrs.end()) {
      return;
    }

    // Skip processing if it's an ignored variable
    if (IgnoreAddresses.find(arg->address) != IgnoreAddresses.end()) {
      //cout << "Ignoring access to: " << hex << arg->address << dec << endl;
      return;
    }

    armaddr_t addr = arg->address;
    armaddr_t size = arg->size;

    if (debug) {
      if (arg->mem_type == MEM_READ)
        cout << "READ at: " << hex << pc << " to addr " << addr << dec << endl;
      else
        cout << "WRITE at: " << hex << pc << " to addr " << addr << dec << endl;
    }

    // If a write to this variable triggers a checkpoint
    if (arg->mem_type == MEM_WRITE && CheckpointAddresses.find(addr) != CheckpointAddresses.end()) {
      checkpoint(pc);

      // Skip the rest, we don't count WARs to a checkpoint variable
      return;
    }

    // Go trough all the bytes and add them to the log
    bool has_war = false;
    bool has_protected_war = false;

    for (armaddr_t i=0; i<size; i++) {
      if (arg->mem_type == MEM_READ) {
        RWL.addRead(addr+i);
      } else if (arg->mem_type == MEM_WRITE) {
        auto R = RWL.addWrite(addr+i);
        has_war = has_war || R.war;
        has_protected_war = has_protected_war || R.protected_war;
      }
    }

    // Log the WAR if it happens
    if (has_war) {
      if (debug) cout << "Has WAR: " << addr << endl;
      PcAddressWarMap[pc][addr] += 1;
    }

    // Increate the checkpoint strength of the last checkpoint
    if (has_protected_war) {
      if (debug) cout << "Has Protected WAR: " << addr << endl;
      addCheckpointStrength(1);
    }

  }
};

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  //HM.add(new TrackVariable(emu));
  auto mf = new CheckpointVerification(emu);
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
