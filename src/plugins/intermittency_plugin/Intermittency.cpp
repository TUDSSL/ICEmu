/**
 *  ICEmu loadable plugin (library)
 *
 * An example ICEmu plugin that is dynamically loaded.
 * This example prints the address of each instruction that is executed.
 *
 * Should be compiled as a shared library, i.e. using `-shared -fPIC`
 */
#include <iostream>
#include <map>
#include <list>
#include <unordered_set>
#include <tuple>

#include "icemu/emu/Emulator.h"
#include "icemu/hooks/HookFunction.h"
#include "icemu/hooks/HookManager.h"
#include "icemu/hooks/RegisterHook.h"
#include "icemu/emu/Function.h"

using namespace std;
using namespace icemu;

// TODO: Need a way to get information from other hooks
class HookInstructionCount : public HookCode {
 public:
  uint64_t count = 0;
  uint64_t pc = 0;

  HookInstructionCount(Emulator &emu) : HookCode(emu, "icnt-ratio") {
  }

  ~HookInstructionCount() {
  }

  void run(hook_arg_t *arg) {
    //(void)arg;  // Don't care
    ++count;
    pc = arg->address;
  }
};
struct InstructionState {
  uint64_t pc;
  armaddr_t mem_address;
  armaddr_t mem_value;
  armaddr_t mem_size;
};

bool operator==(const InstructionState &lhs, const InstructionState &rhs) {
  return lhs.pc == rhs.pc && lhs.mem_address == rhs.mem_address &&
      lhs.mem_value == rhs.mem_value && lhs.mem_size && rhs.mem_size;
}
std::ostream& operator<<(std::ostream &o, const InstructionState &is){
  ios_base::fmtflags f(cout.flags());

  o << "Instruction state PC=0x" << hex << is.pc << " | addr=0x"
    << is.mem_address << " | val=" << dec << is.mem_value
    << " | size=" << is.mem_size;

  cout.flags(f);
  return o;
}

struct CheckpointRegion {
  InstructionState last_instruction;            // The last instruction before the reset
  InstructionState first_changed_instruction;   // The fist instruction that's different
  InstructionState original_instruction;        // The previous state of the changed instruction
};
std::ostream& operator<<(std::ostream &o, const CheckpointRegion &cpr){
  ios_base::fmtflags f(cout.flags());
  cout << hex << "power failure at 0x" << cpr.last_instruction.pc
       << " [first change at 0x" << cpr.first_changed_instruction.pc
       << " was 0x" << cpr.original_instruction.pc << "]";
  cout.flags(f);
  return o;
}

struct MemAccessState {
  armaddr_t address;
  armaddr_t value;
  uint64_t pc;

  MemAccessState(armaddr_t address=0, armaddr_t value=0, uint64_t pc=0)
      : address(address), value(value), pc(pc) {}

  bool operator==(const MemAccessState& t) const{
    return (this->address == t.address);
  }
};
class MemAccessStateHash {
 public:
  size_t operator()(const MemAccessState &t) const { return t.address; }
};

struct WarViolation {
  MemAccessState read;
  MemAccessState write;

  WarViolation(MemAccessState &read, MemAccessState &write)
      : read(read), write(write) {}

  bool operator==(const WarViolation& t) const{
    return (this->read.address == t.read.address &&
            this->read.value == t.read.value && this->read.pc == t.read.pc &&
            this->write.address == t.write.address &&
            this->write.value == t.write.value && this->write.pc == t.write.pc);
  }
};
class WarViolationHash {
 public:
  size_t operator()(const WarViolation &w) const {
    string readstr = to_string(w.read.pc) + to_string(w.read.address) + to_string(w.read.value);
    string writestr = to_string(w.write.pc) + to_string(w.write.address) + to_string(w.write.value);
    return (hash<string>()(readstr+writestr));
  }
};

class WarDetector {
 private:
  bool war = false;

  unordered_set<MemAccessState, MemAccessStateHash> reads;
  unordered_set<MemAccessState, MemAccessStateHash> writes;

  MemAccessState violatingRead;
  MemAccessState violatingWrite;

 public:
  void reset() {
    reads.clear();
    writes.clear();
    war = false;
    violatingRead.pc = 0;
    violatingWrite.pc = 0;
  }

  void addRead(InstructionState &is) {
    MemAccessState mas(is.mem_address, is.mem_value, is.pc);
    reads.insert(mas);
  }

  void addWrite(InstructionState &is) {
    MemAccessState mas(is.mem_address, is.mem_value, is.pc);

    auto wr = writes.find(mas);
    if (wr != writes.end()) {
      // Write already in set. Next write is OK!
    } else {
      // We might have a WAR
      auto rd = reads.find(mas);
      if (rd != reads.end()) {
        // Found in reads, so WAR found!!
        war = true;
        violatingRead = *rd;
        violatingWrite = mas;
      } else {
        // Not yet in reads, so can safely write
        // Add to writes
        writes.insert(mas);
      }
    }
    return;
  }

  bool hasWar() {
    return war;
  }

  void clearWar() {
    war = false;
  }

  MemAccessState getViolatingRead() {
    return violatingRead;
  }

  MemAccessState getViolatingWrite() {
    return violatingWrite;
  }

};

// TODO: Need a way to get information from other hooks
class HookIntermittency : public HookMemory {
 private:
  int new_instructions_after_reset = 0;

  uint64_t new_instructions_count = 0;
  uint64_t redo_instruction_count = 0;
  uint64_t different_execution_count = 0;

  bool verbose = false;
  bool ignore_rwmem = true;

  std::string getLeader() {
    return "[" + name + "] ";
  }

 public:
  HookInstructionCount *hook_instr_cnt;

  list<InstructionState> instructionOrder;
  list<InstructionState>::iterator instructionOrderIt;

  list<CheckpointRegion> checkpointRegions;

  CheckpointRegion checkpointRegion;

  WarDetector warDetector;
  //list<tuple<MemAccessState, MemAccessState>> warViolations;
  unordered_set<WarViolation, WarViolationHash> warViolations;

  HookIntermittency(Emulator &emu) : HookMemory(emu, "intermittency") {
    hook_instr_cnt = new HookInstructionCount(emu);
    resetInstructionTracker();
  }

  ~HookIntermittency() {
    printCheckpointRegions();
    printWarViolations();
  }

  void resetInstructionTracker() {
    instructionOrderIt = instructionOrder.begin();
  }

  void powerFailure() {
    if (verbose)
      cout << getLeader() << "Power failure" << endl;

    // Reset the WAR detection
    warDetector.reset();

    Emulator &emu = getEmulator();

    // Clear the volatile memory
    auto *vmem = emu.getMemory().find("RWMEM");
    memset(vmem->data, 0, vmem->length); // Clear the volatile memory

    // Reset the emulator
    emu.reset();

    resetInstructionTracker();
    new_instructions_after_reset = 0;
  }

  void printCheckpointRegions() {
    for (const auto &cpr : checkpointRegions) {
      cout << "Checkpoint region: " << cpr << endl;
    }
  }

  void printWarViolations() {
    if (warViolations.size() != 0) {

      cout << "WAR violation(s) found!" << endl;
      for (const auto &war : warViolations) {
        auto vread = war.read; //get<0>(war);
        auto vwrite = war.write; //get<1>(war);

        ios_base::fmtflags f(cout.flags());
        cout << hex;
        cout << "Write at: 0x" << vwrite.pc << " to address: 0x"
             << vwrite.address << " with value: 0x" << vwrite.value;
        cout << " after Read at: 0x" << vread.pc << " to address: 0x"
             << vread.address << " with value: 0x" << vread.value << endl;
        cout.flags(f);
      }
    }
  }

  void detectWar(InstructionState &istate, hook_arg_t *arg) {
    // Ignore stack
    if (ignore_rwmem) {
      auto rwmem = getEmulator().getMemory().find("RWMEM");
      if (rwmem != nullptr) {
        if (istate.mem_address >= rwmem->origin &&
            istate.mem_address < (rwmem->origin + rwmem->length)) {
          // Skip the memory in RWMEM
          return;
        }
      }
    }

    // check for WAR
    if (arg->mem_type == MEM_READ) {
      warDetector.addRead(istate);
    } else {
      warDetector.addWrite(istate);
    }
    if (warDetector.hasWar()) {
      auto vread = warDetector.getViolatingRead();
      auto vwrite = warDetector.getViolatingWrite();

      warViolations.insert({vread, vwrite});
      warDetector.clearWar();
      // getchar();

#if 0
      cout << "WAR: ";
      cout << "Write at: 0x" << vwrite.pc << " to address: 0x" << vwrite.address
           << " with value: 0x" << vwrite.value;
      cout << " after Read at: 0x" << vread.pc << " to address: 0x"
           << vread.address << " with value: 0x" << vread.value << endl;
#endif
    }
  }

  void run(hook_arg_t *arg) {

    InstructionState istate = {hook_instr_cnt->pc, arg->address, arg->value,
                               arg->size};

    if (arg->mem_type == MEM_READ) {
      uint64_t memval = 0;
      getEmulator().readMemory(arg->address, (char *)&memval, arg->size);
      istate.mem_value = memval;
    }

    //
    // WAR detection
    //
    detectWar(istate, arg);

#if 0
    if (arg->address == 0x1005ffd0) {
      cout << "hit";
      if (arg->mem_type == MEM_WRITE) {
        cout << " write";
      }
      else {
        cout << " read";
      }
      cout << endl;
      cout << istate << endl;
      getchar();
    }
#endif

    //
    // Power failures
    //
    if (instructionOrderIt == instructionOrder.end()) {
      // We are beond the last recorded instruction
      ++new_instructions_count;
      instructionOrder.push_back(istate); // add the new instruction to the chain

      if (verbose)
        cout << getLeader() << "new instruction " << istate << endl;

      ++new_instructions_after_reset;
      if (new_instructions_after_reset == 1) {
        checkpointRegion.last_instruction = istate;
        powerFailure();
      }
    } else if (istate == *instructionOrderIt) {
      // re-execution is the same
      ++redo_instruction_count;

      if (verbose)
        cout << getLeader() << "re-execution of " << istate << endl;

      instructionOrderIt++;
    } else {
      // re-execution is different
      // we now assume this is ok and a restore to a different checkpoint
      // happened. So we reset the compare chain.
      ++different_execution_count;

      if (verbose)
        cout << getLeader() << "after new checkpoint " << istate << " (was " << *instructionOrderIt << ")" << endl;

      // Add the checkpointregion
      checkpointRegion.first_changed_instruction = istate;
      checkpointRegion.original_instruction = *instructionOrderIt;
      checkpointRegions.push_back(checkpointRegion);

      // Clear the tracker
      while (instructionOrderIt != instructionOrder.end()) {
        //cout << "[erase] " << *instructionOrderIt << endl;
        instructionOrder.erase(instructionOrderIt++);
      }

      instructionOrder.push_back(istate); // add the new instruction to the chain
    }
  }
};

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  auto mf = new HookIntermittency(emu);
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
