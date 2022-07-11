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

#include "PluginArgumentParsing.h"


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
    auto name_arg = PluginArgumentParsing::GetArguments(emu, "putc-logfile=");
    if (name_arg.args.size()) {
      output_file = name_arg.args[0];
      // Open the output file
      output_file_stream.open(output_file, ios::out);
      cout << printLeader() << " writing output to: " << output_file << endl;
    }
  }

  ~MockPutc() {
    cout << color_end;
    if (output_file_stream.is_open()) output_file_stream.close();
  }

  // Hook run
  void run(hook_arg_t *arg) {
    (void)arg;

    auto &arch = getEmulator().getArchitecture();
    char arg_char = arch.functionGetArgument(0);
    //uint32_t arg_file = arch.functionGetArgument(1); // Unused

    cout << color_start << arg_char << color_end;

    if (output_file_stream.is_open()) {
      output_file_stream << arg_char;
    }

    arch.functionSetReturn((uint32_t)arg_char); // Return the character that was printed
    arch.functionSkip();
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
