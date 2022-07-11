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

class FinalValue : public HookCode {
 private:
  vector<string> variable_names;
  vector<const symbol_t *> variable_symbols;

  std::string printLeader() {
    return "[final-value]";
  }

  void processFinalValueArguments() {
    string argument_name = "final-value=";
    for (const auto &a : getEmulator().getPluginArguments().getArgs()) {
      auto pos = a.find(argument_name);
      if (pos != string::npos) {
        auto arg_value = a.substr(pos+argument_name.length());
        variable_names.push_back(arg_value);
      }
    }
  }

 public:
  FinalValue(Emulator &emu) : HookCode(emu, "final_value") {
    /*
     * Never actually run, we are only getting values at the end of the
     * emulation
     */
    type = Hook::TYPE_NONE;

    /*
     * Collect the symbols to print the final value of when the emulation ends
     */
    processFinalValueArguments();
    const symbol_t *var_symbol;
    for (auto fv : variable_names) {
      // Find the address of the variable
      try {
        var_symbol = emu.getMemory().getSymbols().get(fv);
      } catch (...) {
        cout << printLeader() << " could not find symbol: " << fv << endl;
        continue;
      }

      cout << printLeader() << " interested in final value for: " << fv
           << " at address: " << var_symbol->address << endl;
      variable_symbols.push_back(var_symbol);
    }
  }

  ~FinalValue() {
    /*
     * Print the final value of the tracked variables
     */
    for (auto fv : variable_symbols) {
      if (fv->size > sizeof(uint64_t)) {
        cerr << printLeader() << " unsupported symbol size of " << fv->size
             << endl;
        continue;
      }

      uint64_t value = 0;
      auto *value_ptr = getEmulator().getMemory().at(fv->address);
      memcpy(&value, value_ptr, fv->size);
      cout << printLeader() << " final value for: " << fv->name << " = "
           << value << endl;
    }
  }

  // Hook run, should never be called
  void run(hook_arg_t *arg) {
    (void)arg;
  }
};

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  HM.add(new FinalValue(emu));
}

// Class that is used by ICEmu to finf the register function
// NB.  * MUST BE NAMED "RegisterMyHook"
//      * MUST BE global
RegisterHook RegisterMyHook(registerMyCodeHook);
