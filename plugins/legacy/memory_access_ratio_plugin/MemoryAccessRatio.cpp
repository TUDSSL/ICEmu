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

  HookInstructionCount(Emulator &emu) : HookCode(emu, "icnt-ratio") {
  }

  ~HookInstructionCount() {
  }

  void run(hook_arg_t *arg) {
    (void)arg;  // Don't care
    ++count;
  }
};


// TODO: Need a way to get information from other hooks
class HookMemoryAccessRatio : public HookMemory {
 public:
  HookInstructionCount *hook_instr_cnt;
  uint64_t read_count = 0;
  uint64_t write_count = 0;

  map<string, uint64_t> region_read_count;
  map<string, uint64_t> region_write_count;

  struct memregion {
    string name;
    armaddr_t low, high;
  };

  vector<struct memregion> extra_regions;
  void addExtraRegion(Symbols &sym, string sname, string start_symbol, string end_symbol) {
    const symbol_t *s = sym.get(start_symbol);
    if (!s) return;
    auto low = s->address;

    s = sym.get(end_symbol);
    if (!s) return;
    auto high = s->address;

    if (low == high) {
      // Same address, size = 0 => empty section
      return;
    }

    // TODO: Is this true? E.g. is the high always AFTER the stop address?
    high -= 1;

    struct memregion mr;
    mr.name = sname;
    mr.low = low;
    mr.high = high;
    extra_regions.push_back(mr);
  }

  HookMemoryAccessRatio(Emulator &emu) : HookMemory(emu, "memory-access-ratio") {
    hook_instr_cnt = new HookInstructionCount(emu);

    Symbols &sym = getEmulator().getMemory().getSymbols();
    addExtraRegion(sym, "data", "_sdata", "_edata");
    addExtraRegion(sym, "bss", "_sbss", "_ebss");
  }

  ~HookMemoryAccessRatio() {
    uint64_t icount = hook_instr_cnt->count;
    double read_percent = read_count/(double)icount*100;
    double write_percent = write_count/(double)icount*100;
    cout << "[Memory access ratio]"
         << "  Instructions: " << icount
         << ", read: " << read_count << " (" <<read_percent << "%)"
         << ", write: " << write_count << " (" << write_percent << "%)"
         << endl;

    cout << "  Memory access ratio statistics [read] [total: " << read_count << "] (percent_read | percent_all):" << endl;
    for (const auto &rc_kv : region_read_count) {
      double p = rc_kv.second/(double)read_count*100;
      double pt = rc_kv.second/(double)icount*100;
      cout << "    " << rc_kv.first << ": " << rc_kv.second << " (" << p <<"% | " << pt << "%)" << endl;
    }
    cout << "   Memory access ratio statistics [write] (total: " << write_count << ") :" << endl;
    for (const auto &rc_kv : region_write_count) {
      double p = rc_kv.second/(double)write_count*100;
      double pt = rc_kv.second/(double)icount*100;
      cout << "    " << rc_kv.first << ": " << rc_kv.second << " (" << p <<"% | " << pt << "%)" << endl;
    }

  }

  void run(hook_arg_t *arg) {
    armaddr_t address = arg->address;

    auto memseg = getEmulator().getMemory().find(address);
    string memname;
    if (memseg) {
      memname = memseg->name;
    } else {
      memname = "UNKNOWN";
    }

    for (const auto &ar : extra_regions) {
      if (address >= ar.low && address <= ar.high) {
        memname = memname + ":" + ar.name;
        // TODO break loop, not now for testing
      }
    }

    if (arg->mem_type == HookMemory::MEM_READ) {
      region_read_count[memname] += 1;
      ++read_count;
    } else {
      region_write_count[memname] += 1;
      ++write_count;
    }
  }
};

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  auto mf = new HookMemoryAccessRatio(emu);
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
