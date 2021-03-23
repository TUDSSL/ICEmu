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
#include <algorithm>
#include <fstream>

#include "icemu/emu/Emulator.h"
#include "icemu/hooks/HookFunction.h"
#include "icemu/hooks/HookManager.h"
#include "icemu/hooks/RegisterHook.h"
#include "icemu/emu/Function.h"
#include "icemu/emu/Symbols.h"

using namespace std;
using namespace icemu;


// TODO: Need a way to get information from other hooks
class HookInstructionCount : public HookCode {
 private:
  const char func_type = 2; // magic ELF function type

 public:
  uint64_t count = 0;
  uint64_t pc = 0;

  const string unknown_function_str = "UNKNOWN_FUNCTION";
  struct FunctionFrame {
    const string *function_name = nullptr;
    armaddr_t function_address = 0;
    uint64_t function_entry_icount = 0;
    armaddr_t sp_function_entry = 0;
    armaddr_t LR = 0;
  };
  list<FunctionFrame> callstack;


  armaddr_t estack;

  // A boolean that is true on the first instruction of a new function
  // NB. This is hacky, but new_function acts like an ISR flag
  // it needs to be manually reset after reading
  bool new_function = true;
  list<FunctionFrame> function_entries; // is cleared by the HookIdempotencyStatistics class

  // Map from an address to a function
  map<armaddr_t, const string *> function_map;
  map<armaddr_t, const string *> function_entry_map;

  // A map holding ALL executed instructions and the number of times they have
  // been executed
  const bool track_instruction_execution = true;
  map<armaddr_t, uint64_t> instruction_execution_map;

  HookInstructionCount(Emulator &emu) : HookCode(emu, "icnt-idempotency-stats") {
    auto &symbols = getEmulator().getMemory().getSymbols();
    for (const auto &sym : symbols.symbols) {
      if (sym.type == func_type) {
        //cout << "Func addr: " << sym.address << " - " << sym.getFuncAddr() << endl;
        //cout << "Func name: " << sym.name << endl;
        //cout << "Func size: " << sym.size << endl;

        // To check for function entries only
        function_entry_map[sym.getFuncAddr()] = &sym.name;


        // Add ALL the possible addresses in the function to the map
        // Return the function name if it's in any of the addresses in the
        // function.
        // Assmumtions:
        //  * All opcodes are 16-bit (2 bytes) or more in multiple
        //  * Functions are continious (we use the size for functions)

        for (armaddr_t faddr=sym.getFuncAddr(); faddr<sym.getFuncAddr()+sym.size; faddr+=2) {
          function_map[faddr] = &sym.name;
        }
      }
    }

    auto estack_sym = symbols.get("_estack");
    estack = estack_sym->address;
    cout << "Estack at: " << estack << endl;

#if 0
    cout << "Plugin arguments:" << endl;
    auto &plugin_args = emu.getPluginArguments();
    for (const auto &a : plugin_args.getArgs()) {
      cout << "Plugin arg: " << a << endl;
    }
#endif
  }

  ~HookInstructionCount() {
    cout << "Call stack size at the end of the program: " << callstack.size()
         << " (should be 2)" << endl;
  }

  const string *isFunctionEntry(armaddr_t addr) {
    auto f = function_entry_map.find(addr);
    if (f != function_entry_map.end()) {
      return f->second;
    }
    return nullptr;
  }

  const string *inFunction(armaddr_t addr) {
    auto f = function_map.find(addr);
    if (f == function_map.end()) {
      //cout << "Executing address that does not belong to any function ("
      //     << addr << ")" << endl;
      //while (1) {}
      return nullptr;
    }
    return f->second;
  }

  void trackFunctions(armaddr_t addr) {

    // Check if this is a function entry
    // If so, we mark it as such
    const string *function_entry = isFunctionEntry(addr);
    if (function_entry != nullptr) {
      //cout << "Address: " << addr << " Function entry: " << *function_entry << endl;
      struct FunctionFrame callframe;
      callframe.function_name = function_entry;
      callframe.function_address = addr;
      callframe.function_entry_icount = count;
      callframe.sp_function_entry = getEmulator().getRegisters().get(Registers::SP);
      callframe.LR = getEmulator().getRegisters().get(Registers::LR) & ~0x1;

      callstack.push_back(callframe);
      //cout << "callframe size: " << callstack.size() << endl;
      //cout << "LR: " << callframe.LR << endl;

      // Set new function flag
      function_entries.push_back(callframe);
      new_function = true;

      return;
    }

    if (callstack.back().LR == addr) {
      // We left the function and are back at the LR
      // We pop stack frames until we are the current function
      // This is because a function can use a "normal" branch to jump to the
      // start of the function. If that's the case we DO detect it in
      // the function entry check. So we need to unwind here if that happened.
      const string *function_current = inFunction(addr);
      while (callstack.back().function_name != function_current) {
        callstack.pop_back();
      }
      //cout << "Function exit to: " << *callstack.back().function_name << endl;
      //cout << "callframe size: " << callstack.size() << endl;
    }

    // Else we are somewhere in the same function
  }

  void run(hook_arg_t *arg) {
    //(void)arg;  // Don't care
    ++count;
    pc = arg->address;

    trackFunctions(arg->address);

    // Track the number of times this instruction was executed
    if (track_instruction_execution) {
      instruction_execution_map[pc] += 1;
    }
  }
};

struct InstructionState {
  uint64_t pc;
  uint64_t icount;
  armaddr_t mem_address;
  armaddr_t mem_size;
  armaddr_t function_address;
  const string *function_name;
};

struct MemAccessState {
  armaddr_t address;
  uint64_t pc;
  uint64_t icount;

  MemAccessState(armaddr_t address = 0, uint64_t pc = 0, uint64_t icount = 0)
      : address(address), pc(pc), icount(icount) {}

  bool operator==(const MemAccessState& t) const{
    return (this->address == t.address);
  }
};
class MemAccessStateHash {
 public:
  size_t operator()(const MemAccessState &t) const { return t.address; }
};


struct WarLogLine {
  uint64_t read_instruction_count;
  uint64_t write_instruction_count;
  uint64_t read_code_address;
  uint64_t write_code_address;
  armaddr_t memory_address;
  armaddr_t function_address;
  string function_name;
  uint32_t access_type;
  const string *access_type_str;
  uint32_t region_end_type;
  const string *region_end_type_str;
};
std::ostream& operator<<(std::ostream &o, const WarLogLine &l){
  char d = ',';

  o << l.read_instruction_count << d
    << l.write_instruction_count << d
    << l.read_code_address << d
    << l.write_code_address << d
    << l.memory_address << d
    << l.function_address << d
    << l.function_name << d
    << l.access_type << d
    << *l.access_type_str << d
    << l.region_end_type << d
    << *l.region_end_type_str;

  return o;
}

class WarLog {
 private:
  list<WarLogLine> warLogLines;
  string filename;

 public:
  WarLog(const string &_filename) {
    filename = _filename;
  }

  void add(WarLogLine &log) {
    warLogLines.push_back(log);
  }

  void write(string prefix="./") {
    string filename_cmplt = prefix+"/"+filename;
    ofstream f(filename_cmplt);
    if (!f.is_open()) {
      cout << "Error opening log file: " << filename_cmplt << endl;
      return;
    }

    for (const auto &l : warLogLines) {
      f << l << endl;
      //cout << l << endl;
    }
  }

};

class WarDetector {
 private:
  bool detect_protected_war; // WRW is OK
  //bool war;
  //bool protected_war;

  unordered_set<MemAccessState, MemAccessStateHash> reads;
  unordered_set<MemAccessState, MemAccessStateHash> writes;

  MemAccessState violatingRead;
  MemAccessState violatingWrite;

 public:
  WarLog log;

  WarDetector(const string &logfile, bool detect_protected_war = true)
      : detect_protected_war(detect_protected_war), log(logfile) {
    reset();
  }

  void reset() {
    reads.clear();
    writes.clear();
    //war = false;

    violatingRead.pc = 0;
    violatingWrite.pc = 0;
  }

  void addRead(MemAccessState &mas) {
    auto rd = reads.find(mas);
    if (rd != reads.end()) {
      // if it's aready in the read set we update it (new pc and/or icount)
      reads.erase(rd);
    }
    reads.insert(mas);
  }

  void addRead(InstructionState &is) {
    MemAccessState mas(is.mem_address, is.pc, is.icount);

    auto mem_size = is.mem_size;
    for (armaddr_t i=0; i<mem_size; i++) {
      MemAccessState mas_byte = mas;
      mas_byte.address += i;
      addRead(mas_byte);
    }

    //addRead(mas);
  }

  bool addWrite(MemAccessState &mas) {
    bool war;

    auto rd = reads.find(mas);
    auto wr = writes.find(mas);

    bool rd_before = (rd != reads.end()); // read happended (true)
    bool wr_before = (wr != writes.end()); // write happended (true)

    if (wr_before == true && rd_before == true) {
      // WRW -> protected WAR
      if (detect_protected_war) {
        // protected war is ignored
        // WRW -> protected
        war = false;
      } else {
        // We do not consider protecting writes
        // RW -> war
        war = true;
        violatingRead = *rd;
        violatingWrite = mas;
      }
    } else if (wr_before == false && rd_before == true) {
      // RW -> WAR
      war = true;
      violatingRead = *rd;
      violatingWrite = mas;
    } else if (wr_before == true && rd_before == false) {
      // WW -> No WAR
      war = false;
      // update the write (the last one counts);
      writes.erase(wr);
      writes.insert(mas);
    } else {
      // W -> No WAR
      war = false;
      writes.insert(mas); // Add to writes
    }

    return war;
  }

  bool addWrite(InstructionState &is) {
    MemAccessState mas(is.mem_address, is.pc, is.icount);

    bool war = false;

    auto mem_size = is.mem_size;
    for (armaddr_t i=0; i<mem_size; i++) {
      MemAccessState mas_byte = mas;
      mas_byte.address += i;
      bool war_byte = addWrite(mas_byte);

      if (war_byte == true) {
        war = true;
      }
    }

    //addWrite(mas);
    return war;
  }

  MemAccessState getViolatingRead() {
    return violatingRead;
  }

  MemAccessState getViolatingWrite() {
    return violatingWrite;
  }
};

// TODO: Need a way to get information from other hooks
class HookIdempotencyStatistics : public HookMemory {
 private:
  std::string getLeader() {
    return "[" + name + "] ";
  }

  enum MemAccessType {
    UNKNOWN = 0,
    MEM_NONE,
    MEM_LOCAL,
    MEM_STACK,
    MEM_GLOBAL,
  };

  const string MemAccessTypeStr[5] = {
      "UNKNOWN",
      "NONE",
      "LOCAL",
      "STACK",
      "GLOBAL",
  };

  enum RegionEndType {
    RE_WAR = 0,
    RE_FUNCTION_ENTRY,
    RE_SIZE_LIMIT,
    RE_FORCED
  };

  const string RegionEndTypeStr[4] = {
    "WAR",
    "FUNCTION_ENTRY",
    "SIZE_LIMIT",
    "FORCED"
  };

  uint64_t max_idempotent_secion_size = 1000; // The maximum size of an idempotent section, 0 is unlimited

 public:
  HookInstructionCount *hook_instr_cnt;

  //
  // Different WAR detectors
  //

  // Intra-procedural, detects across function boundaries
  WarDetector warDetector {"idempotent-sections-intra-procedural.csv", true}; // Takes protecting writes into account -> WRW is NOT a WAR

  // Inter-procedural, section is ended when entering a function
  WarDetector warDetectorInterProcedural {"idempotent-sections-inter-procedural-dump.csv", true}; // Takes protecting writes into account -> WRW is NOT a WAR

  // Ignores protecting writes -> WRW is WAR
  // Intra-procedural, detects across function boundaries
  WarDetector warDetectorNoProtected {"idempotent-sections-no-protected-intra-procedural-dump.csv", false};

  // Ignores protecting writes -> WRW is WAR
  // Inter-procedural, section is ended when entering a function
  WarDetector warDetectorNoProtectedInterProcedural {"idempotent-sections-no-protected-inter-procedural-dump.csv", false};


  HookIdempotencyStatistics(Emulator &emu) : HookMemory(emu, "idempotent-stats") {
    hook_instr_cnt = new HookInstructionCount(emu);
  }

  ~HookIdempotencyStatistics() {
    cout << "Dumping log files" << endl;

    string out_dir;

    // Create a directory if the argument:
    // idempotent-stats-output-dir=output_dir
    string find_arg="idempotent-stats-output-dir=";
    for (const auto &a : getEmulator().getPluginArguments().getArgs()) {
      auto pos = a.find(find_arg);
      if (pos != string::npos) {
        out_dir = a.substr(pos+find_arg.length());
        break;
      }
    }

    cout << "Output directory: " << out_dir << endl;

    warDetector.log.write(out_dir);
    warDetectorInterProcedural.log.write(out_dir);
    warDetectorNoProtected.log.write(out_dir);
    warDetectorNoProtectedInterProcedural.log.write(out_dir);

    // Output the instruction_execution_map data
    // Done here becuase it's part of the idemp. stats and we already have the
    // directory
    if (hook_instr_cnt->track_instruction_execution == true) {
      string instruction_execution_filename = out_dir + "/" + "instruction-exection-count-map.csv";
      ofstream f(instruction_execution_filename);
      if (!f.is_open()) {
        cout << "Error opening log file: " << instruction_execution_filename << endl;
        return;
      }

      for (const auto &m : hook_instr_cnt->instruction_execution_map) {
        // First the address, then the number of times that it was executed
        f << m.first << "," << m.second << endl;
      }
    }
  }

  enum MemAccessType getMemAccessType(InstructionState &istate) {
    auto address = istate.mem_address;
    auto estack_sp = hook_instr_cnt->estack;
    auto f_entry_sp = hook_instr_cnt->callstack.back().sp_function_entry;
    auto f_current_sp = getEmulator().getRegisters().get(Registers::SP);

    // Memory access is local if the address is larger than the current stack
    // pointer, but below the entry sp
    if (address >= f_current_sp && address < f_entry_sp) {
      // Function-local memory
      return MEM_LOCAL;
    }

    // Memory access is stack if it's larger than the current stack and pointer
    // but below the _estack (end of the stack)
    else if (address >= f_current_sp && address < estack_sp) {
      return MEM_STACK;
    }

    // Other memory accesses we regard as "Global"
    else {
      return MEM_GLOBAL;
    }

  }

#if 0
  // Callback called when a new function is entered
  // TODO: add to the callback, and want to decide if we want to track
  // what happens if we only put a checkpoint on functions when they ALSO
  // generate a WAR (just only take the last one when a WAR happens like we do
  // now
  // TODO: what happens if we only do the last one before a WAR?
  void addNewFunctionEntryWarCallBack(armaddr_t function_address, string &function_name, uint64_t icount) {

  }
#endif

  bool detectWar(WarDetector &wd, InstructionState &istate, bool is_read, bool inter_procedural=false) {
    bool war_detected = false;

    // If we are intra procedural, we keep tracking when entering a new
    // function. If we are *inter* procedural we end the idempotent section
    // and reset the tracker if we enter a new function
    if (inter_procedural == true && hook_instr_cnt->new_function == true) {
      // End the idempotent region and reset the tracker
      // All zero to indicate a forced checkpoint
      WarLogLine l = {0,  // read icount
                      hook_instr_cnt->callstack.back().function_entry_icount,  // write icount
                      0,  // read.pc
                      0,  // write.pc
                      0,  // memory address
                      istate.function_address,
                      *istate.function_name,
                      1,  // mem_type,
                      &MemAccessTypeStr[1],
                      RE_FUNCTION_ENTRY,
                      &RegionEndTypeStr[RE_FUNCTION_ENTRY]};
      wd.log.add(l); // Add the end of the region
      wd.reset(); //
    }

    bool has_war = false;

    // check for WAR
    if (is_read) {
      wd.addRead(istate);
    } else {
      has_war = wd.addWrite(istate);
    }

    if (has_war) {
      // A WAR happened, so we break the section just before the write
      // and add the write to the warDetector
      auto read = wd.getViolatingRead();
      auto write = wd.getViolatingWrite();

      // Check if the memory is function-local, stack or global (stack of prev.
      // function)
      auto mem_type = getMemAccessType(istate);

      WarLogLine l = {read.icount,
                      write.icount,
                      read.pc,
                      write.pc,
                      read.address,
                      istate.function_address,
                      *istate.function_name,
                      mem_type,
                      &MemAccessTypeStr[mem_type],
                      RE_WAR,
                      &RegionEndTypeStr[RE_WAR]};
      wd.log.add(l);

      wd.reset(); // The end of an idempotent section (a "checkpoint")
      wd.addWrite(istate); // We know it was a write, as only a write can trigger a WAR

      war_detected = true;

      //ios_base::fmtflags f(cout.flags());
      //cout << hex;
      //cout << "WAR at code: 0x" << l.write_code_address << " memory: 0x" << l.memory_address << endl;
      //cout.flags(f);
    }
    return war_detected;
  }

  void run(hook_arg_t *arg) {
    InstructionState istate = {hook_instr_cnt->pc,
                               hook_instr_cnt->count,
                               arg->address,
                               arg->size,
                               hook_instr_cnt->callstack.back().function_address,
                               hook_instr_cnt->callstack.back().function_name};
    //
    // WAR detection
    //

    bool is_read;
    if (arg->mem_type == MEM_READ) {
      is_read = true;
    } else {
      is_read = false;
    }

    // Inra-procedural detectors
    detectWar(warDetector, istate, is_read);
    detectWar(warDetectorNoProtected, istate, is_read);

    // Inter-procedural detectors
    detectWar(warDetectorInterProcedural, istate, is_read, true);
    detectWar(warDetectorNoProtectedInterProcedural, istate, is_read, true);

    hook_instr_cnt->new_function = false; // reset the status (see NB)
  }
};

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  auto mf = new HookIdempotencyStatistics(emu);
  if (mf->getStatus() == Hook::STATUS_ERROR) {
    delete mf->hook_instr_cnt;
    delete mf;
    return;
  }
  HM.add(mf->hook_instr_cnt);
  HM.add(mf);
}

// Class that is used by ICEmu to find the register function
// NB.  * MUST BE NAMED "RegisterMyHook"
//      * MUST BE global
RegisterHook RegisterMyHook(registerMyCodeHook);
