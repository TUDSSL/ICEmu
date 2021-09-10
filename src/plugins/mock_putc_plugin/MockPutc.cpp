/**
 *  ICEmu loadable plugin (library)
 *
 * An example ICEmu plugin that is dynamically loaded.
 * This example prints the address of each instruction that is executed.
 *
 * Should be compiled as a shared library, i.e. using `-shared -fPIC`
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

class MockPutc : public HookFunction {

 public:
  bool use_color = true;
  string color_start = "\033[1m";
  string color_end = "\033[0m";

  string output_file;
  ofstream output_file_stream;

  std::string printLeader() {
    return "[mock-putc]";
  }

  // Always execute
  MockPutc(Emulator &emu, string fname) : HookFunction(emu, fname) {
    // Get where to store the log file (if any)
    string argument_name = "putc-logfile=";
    for (const auto &a : getEmulator().getPluginArguments().getArgs()) {
      auto pos = a.find(argument_name);
      if (pos != string::npos) {
        auto arg_value = a.substr(pos+argument_name.length());

        output_file = arg_value;
        if (output_file == "%") {
          output_file = getEmulator().getElfDir() + "/" + getEmulator().getElfName() + ".stdout";
        }

        // Open the output file
        output_file_stream.open(output_file, ios::out);

        cout << printLeader() << " writing output to: " << output_file << endl;
        break;
      }
    }

  }

  ~MockPutc() {
    cout << color_end;
    if (output_file_stream.is_open()) output_file_stream.close();
  }

  // Hook run
  void run(hook_arg_t *arg) {
    (void)arg;
    Registers &reg = getRegisters();

    Function::Argument<char> farg_char;
    Function::Argument<uint32_t> farg_file; // Unused
    Function::Arguments::parse(reg, farg_char, farg_file);

    cout << color_start << farg_char.arg << color_end;

    if (output_file_stream.is_open()) {
      output_file_stream << farg_char.arg;
    }

    Function::skip(reg, farg_char.arg);
  }
};

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  auto mf = new MockPutc(emu, "putc");
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
