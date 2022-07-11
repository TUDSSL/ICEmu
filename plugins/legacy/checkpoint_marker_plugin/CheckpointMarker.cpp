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

class CheckpointMarker : public HookCode {

 private:
  vector<const symbol_t *> function_symbols;

  bool has_csv_output = false;
  string csv_output;

  map<const symbol_t *, uint64_t> FunctionCallMap;

  std::string printLeader() {
    return "[checkpoint-marker]";
  }

  void collectMarkerFunctions() {
    auto &Symbols = getEmulator().getMemory().getSymbols();
    //string Marker = "__checkpoint_marker_";
    string Marker = "__checkpoint";

    for (auto &S : Symbols.symbols) {
      auto &str = S.name;
      if (str.rfind(Marker, 0) == 0) {
        // Found a marker
        cout << printLeader() << " found marker function: " << S.name << endl;
        function_symbols.push_back(&S);
      }
    }

  }

 public:
  // Always execute
  CheckpointMarker(Emulator &emu) : HookCode(emu, "checkpoint_marker") {
    // Get the functions to track
    collectMarkerFunctions();

    // Get where to store the csv
    string argument_name = "checkpoint-marker-file=";
    for (const auto &a : getEmulator().getPluginArguments().getArgs()) {
      auto pos = a.find(argument_name);
      if (pos != string::npos) {
        auto arg_value = a.substr(pos+argument_name.length());

        csv_output = arg_value;
        if (csv_output == "%") {
          csv_output = getEmulator().getElfDir() + "/" + getEmulator().getElfName() + ".checkpointmarker.csv";
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

  ~CheckpointMarker() {

    ofstream CheckpointMarkerFile;
    if (has_csv_output) {
      CheckpointMarkerFile.open(csv_output);
      if (!CheckpointMarkerFile.is_open()) {
        has_csv_output = false;
      }
    }

    uint64_t total_cnt = 0;
    for (auto &p : FunctionCallMap) total_cnt += p.second;

    for (auto &p : FunctionCallMap) {
      auto sym = p.first;
      auto cnt = p.second;

      float percent = cnt/(float)total_cnt*100.0;

      if (has_csv_output)
        CheckpointMarkerFile << sym->name << "," << cnt << "," << percent
                             << endl;

      cout << printLeader() << " " << cnt << " (" << percent << "%) " << sym->name
           << endl;
    }
  }

  armaddr_t getBrachAddress(armaddr_t address, armaddr_t size) {
    bool ok;
    uint8_t instruction[size];
    armaddr_t branch_addr = 0;

    ok = getEmulator().readMemory(address, (char *)instruction, size);
    if (!ok) {
      cerr << printLeader() << " failed to read memory for instruction at address " << address << endl;
      return 0;
    }
    cs_insn *insn;
    size_t cnt = cs_disasm(*getEmulator().getCapstoneEngine(), instruction, size, address, 0, &insn);
    if (cnt == 0) {
      cerr << printLeader() << " failed to disasemble instruction at address " << address << endl;
      return 0;
    }

    string mnemonic(insn[0].mnemonic);
    string addr_str(insn[0].op_str);
    if (mnemonic == "bl") {
      string addr_hex_str = addr_str.substr(1);
      branch_addr = stoi(addr_hex_str, nullptr, 16);
    }

    cs_free(insn, cnt);

    return branch_addr;
  }

  // Hook run
  void run(hook_arg_t *arg) {

    auto call_addr = getBrachAddress(arg->address, arg->size);
    if (call_addr == 0) return;

    for (auto &f : function_symbols) {
      if (f->getFuncAddr() == call_addr) {
        //cout << printLeader() << " found call to: " << f->name << endl;
        FunctionCallMap[f]++;

        // Skip the call
        auto &Reg = getEmulator().getRegisters();
        auto PC = Reg.get(Registers::PC);
        auto NewPC = PC + arg->size+1; // thumb is off by one

        //auto LR = Reg.get(Registers::LR);
        //cout << "PC: " << std::hex << PC << " LR: " << LR << " NEW: " << NewPC << std::dec << std::endl;

        // Skip the call
        Reg.set(Registers::PC, NewPC);

        // Can only be one function
        return;
      }
    }
  }
};

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  auto mf = new CheckpointMarker(emu);
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
