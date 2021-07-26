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

class CallsiteCount : public HookCode {

 private:
  vector<string> function_names;
  vector<const symbol_t *> function_symbols;

  bool has_csv_output = false;
  string csv_output;

  map<armaddr_t, uint64_t> AddressCountMap;

  typedef pair<armaddr_t, uint64_t> addrpair_t;

  // Comparator function to sort pairs
  // according to second value
  static bool cmp(addrpair_t &a, addrpair_t &b) {
    return a.second > b.second;
  }

  // Function to sort the map according
  // to value in a (key-value) pairs
  vector<addrpair_t> sort(map<armaddr_t, uint64_t> &M) {
    // Declare vector of pairs
    vector<addrpair_t> A;

    // Copy key-value pair from Map
    // to vector of pairs
    for (auto &it : M) {
      A.push_back(it);
    }

    // Sort using comparator function
    std::sort(A.begin(), A.end(), cmp);

    // Print the sorted value
    //uint64_t total = 0;
    //for (auto &it : A) {
    //  cout << printLeader() << " 0x" << hex << it.first << dec << ' ' << it.second << endl;
    //  total += it.second;
    //}
    //cout << printLeader() << " TOTAL: " << total << endl;

    return A;
  }

  std::string printLeader() {
    return "[callsite-count]";
  }

  void processCallsiteCountTrackArguments() {
    string argument_name = "callsite-count-track=";
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
  CallsiteCount(Emulator &emu) : HookCode(emu, "callsite_count") {
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

      cout << printLeader() << " tracking call count for: " << f
           << " at address: 0x" << hex << func_symbol->getFuncAddr() << dec << endl;
      function_symbols.push_back(func_symbol);
    }

    // Get where to store the csv
    string argument_name = "callsite-count-file=";
    for (const auto &a : getEmulator().getPluginArguments().getArgs()) {
      auto pos = a.find(argument_name);
      if (pos != string::npos) {
        auto arg_value = a.substr(pos+argument_name.length());

        csv_output = arg_value;
        if (csv_output == "%") {
          csv_output = getEmulator().getElfDir() + "/" + getEmulator().getElfName() + ".callsitecount.csv";
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

  ~CallsiteCount() {
    auto AddressCountVec = sort(AddressCountMap);

    ofstream CallsiteCountFile;
    if (has_csv_output) {
      CallsiteCountFile.open(csv_output);
      if (!CallsiteCountFile.is_open()) {
        has_csv_output = false;
      }
    }

    // Print the top X if we also write to a file
    // Otherwise print it all
    int printed = 0;
    int printex_max = 5;

    uint64_t total = 0;
    for (auto &p : AddressCountVec) {
      auto addr = p.first;
      auto cnt = p.second;
      total += cnt;

      if (has_csv_output) {
        CallsiteCountFile << "0x" << hex << addr << dec << "," << cnt << "\n";
      }

      if (!has_csv_output || printed < printex_max) {
        ++printed;
        cout << printLeader() << " 0x" << hex << addr << dec << ' ' << cnt
             << endl;
      }
    }

    cout << printLeader() << " TOTAL: " << total << endl;
  }

  // Hook run
  void run(hook_arg_t *arg) {
    auto addr = arg->address;

    for (auto &f : function_symbols) {
      if (f->getFuncAddr() == addr) {
        auto &reg = getEmulator().getRegisters();
        armaddr_t callsite_addr = getCallAddr(reg.get(Registers::LR));
        AddressCountMap[callsite_addr]++;
      }
    }
  }
};

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  auto mf = new CallsiteCount(emu);
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
