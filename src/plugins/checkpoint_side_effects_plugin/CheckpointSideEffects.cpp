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
  const symbol_t *checkpoint_function = nullptr;
  armaddr_t post_checkpoint_address = 0;

  std::string printLeader() {
    return "[checkpoint-side-effects]";
  }

  map<Registers::reg, armaddr_t> RegisterValueMap;
  std::ostringstream RegBeforeStream;

  void findCheckpointFunction() {
    auto &Symbols = getEmulator().getMemory().getSymbols();

    for (auto &S : Symbols.symbols) {
      if (S.name == "__checkpoint") {
        checkpoint_function = &S;
        cout << printLeader() << " found checkpoint function: " << S.name
             << " at address: 0x" << hex << S.address << dec << endl;
        break;
      }
    }
  }

 public:
  // Always execute
  CheckpointMarker(Emulator &emu) : HookCode(emu, "checkpoint_marker") {
    // Get the functions to track
    findCheckpointFunction();
  }

  armaddr_t getCallAddr(armaddr_t address) const {
    return (address & ~0x1) - 4;
  }

  ~CheckpointMarker() {
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

  void saveRegisters(Registers &Reg) {
    RegisterValueMap[Registers::R0]   = Reg.get(Registers::R0);
    RegisterValueMap[Registers::R1]   = Reg.get(Registers::R1);
    RegisterValueMap[Registers::R2]   = Reg.get(Registers::R2);
    RegisterValueMap[Registers::R3]   = Reg.get(Registers::R3);
    RegisterValueMap[Registers::R4]   = Reg.get(Registers::R4);
    RegisterValueMap[Registers::R5]   = Reg.get(Registers::R5);
    RegisterValueMap[Registers::R6]   = Reg.get(Registers::R6);
    RegisterValueMap[Registers::R7]   = Reg.get(Registers::R7);
    RegisterValueMap[Registers::R8]   = Reg.get(Registers::R8);
    RegisterValueMap[Registers::R9]   = Reg.get(Registers::R9);
    RegisterValueMap[Registers::R10]  = Reg.get(Registers::R10);
    RegisterValueMap[Registers::R11]  = Reg.get(Registers::R11);
    RegisterValueMap[Registers::R12]  = Reg.get(Registers::R12);
    RegisterValueMap[Registers::R13]  = Reg.get(Registers::R13);
    RegisterValueMap[Registers::R14]  = Reg.get(Registers::R14);
    RegisterValueMap[Registers::R15]  = Reg.get(Registers::R15);
    RegisterValueMap[Registers::APSR] = Reg.get(Registers::APSR);
  }

  bool compareRegisters(Registers &Reg) {
    if (
    (RegisterValueMap[Registers::R0]   == Reg.get(Registers::R0)) &&
    (RegisterValueMap[Registers::R1]   == Reg.get(Registers::R1)) &&
    (RegisterValueMap[Registers::R2]   == Reg.get(Registers::R2)) &&
    (RegisterValueMap[Registers::R3]   == Reg.get(Registers::R3)) &&
    (RegisterValueMap[Registers::R4]   == Reg.get(Registers::R4)) &&
    (RegisterValueMap[Registers::R5]   == Reg.get(Registers::R5)) &&
    (RegisterValueMap[Registers::R6]   == Reg.get(Registers::R6)) &&
    (RegisterValueMap[Registers::R7]   == Reg.get(Registers::R7)) &&
    (RegisterValueMap[Registers::R8]   == Reg.get(Registers::R8)) &&
    (RegisterValueMap[Registers::R9]   == Reg.get(Registers::R9)) &&
    (RegisterValueMap[Registers::R10]  == Reg.get(Registers::R10)) &&
    (RegisterValueMap[Registers::R11]  == Reg.get(Registers::R11)) &&
    (RegisterValueMap[Registers::R12]  == Reg.get(Registers::R12)) &&
    (RegisterValueMap[Registers::R13]  == Reg.get(Registers::R13)) &&
    (RegisterValueMap[Registers::R14]  == Reg.get(Registers::R14)) &&
    (RegisterValueMap[Registers::APSR] == Reg.get(Registers::APSR))
    ){
      return true;
    }
    return false;
  }

  void printRegisterMap(void) {
  }

  // Hook run
  void run(hook_arg_t *arg) {
    if (checkpoint_function == nullptr) return;

    if (post_checkpoint_address == arg->address) {
      auto &Reg = getEmulator().getRegisters();
      if (compareRegisters(Reg) == false) {
        // Check if a returned checkpoint call has the same registers
        cout << printLeader() << "Registers where:" << endl;
        cout << RegBeforeStream.str() << endl;

        cout << endl;
        cout << printLeader() << "Registers are: " << endl;
        Reg.dump();

        cout << "Registers are not the same before and after the checkpoint!" << endl;
        //getEmulator().stop("Checkpoint error");
      } else {
        cout << printLeader() << "Registers where:" << endl;
        cout << RegBeforeStream.str() << endl;

        cout << endl;
        cout << printLeader() << "Registers are: " << endl;
        Reg.dump();

        cout << printLeader() << " matiching checkpoint" << endl;
      }
    }

    // Store the registers before a checkpoint call
    auto call_addr = getBrachAddress(arg->address, arg->size);
    if (call_addr == 0) return;

    if (checkpoint_function->getFuncAddr() == call_addr) {

      // Get the registers before the call
      auto &Reg = getEmulator().getRegisters();
      saveRegisters(Reg);
      RegBeforeStream.str(string());

      Reg.dump(RegBeforeStream);

      auto PC = Reg.get(Registers::PC);
      auto NewPC = PC + arg->size;

      cout << printLeader() << " checkpoint address: " << hex << PC << dec << endl;
      cout << printLeader() << " post address: " << hex << NewPC << dec << endl;

      post_checkpoint_address = NewPC;
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
