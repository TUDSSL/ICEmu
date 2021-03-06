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
#include "icemu/hooks/HookCode.h"
#include "icemu/hooks/HookManager.h"
#include "icemu/hooks/RegisterHook.h"


using namespace std;
using namespace icemu;

#include <csignal>

extern void main_signal_handler(int signal);

static volatile atomic<bool> stop_plugin;
static volatile atomic<bool> continue_in_progress;

static void signal_handler(int signal) {
  // A signal occured
  //cout << "Captured plugin signal" << endl;
  if (continue_in_progress) {
    //cout << "Stopping continue command" << endl;
    continue_in_progress = false;
  } else {
    cout << endl << "Press ENTER to quit" << endl;
    stop_plugin = true;
    main_signal_handler(signal);
  }
}

class StepInstructions : public HookCode {
 private:
  string printLeader() {
    return "(icemu) ";
  }

  size_t skipnext = 0;
  armaddr_t stopaddress = 0;

  void setStopAddress(armaddr_t addr) {
    stopaddress = addr;
    continue_in_progress = true;
  }

  void clearStopAddress() {
    stopaddress = 0;
    continue_in_progress = false;
  }

  void help() {
    cout << "Plugin " << name << " usage:" << endl
         << "Commands:" << endl
         << "  s [repeat]    execute a single instruction 'repeat' times" << endl
         << "                  default = 1" << endl
         << "  [none]        no/empty command, same as 's'" << endl
         << "  c [address]   execute untill instruction address 'address'"<< endl
         << "                  default run until interupted" << endl
         << "  r             dump the registers" << endl
         << "  quit          stop emulation" << endl
         << "  help          show this message" << endl
         << "Control:" << endl
         << "  CTRL-C        if continue ('c') command is running halt execution," << endl
         << "                  otherwise same as 'quit'" << endl
         ;
  }

 public:
  // Always execute
  StepInstructions(Emulator &emu) : HookCode(emu, "step_instructions") {

    // Setup signal handler
    stop_plugin = false;
    continue_in_progress = false;
    signal(SIGINT, signal_handler);

    help();
  }

  ~StepInstructions() {
  }

  bool StepInstruction(armaddr_t address) {

    if (skipnext != 0) {
      --skipnext;
      return true;
    }

    if (continue_in_progress && stopaddress != address) {
      return true;
    } else {
      clearStopAddress();
    }


    string command;
    regex rgx("\\s*([a-zA-Z]+)\\s*([^\\s]*)\\s*([^\\s]*)");
    smatch matches;
    // Match complete = 0; command = 1; repeat = 2
    const size_t match_command = 1;
    const size_t match_repeat = 2;
    const size_t match_address = 2;
		const size_t match_length = 3;

    // Get a command
    cout << printLeader();
    getline(cin, command);

    if (stop_plugin) {
      return true;
    }

    if (command.length() == 0) {
      cout << "\x1b[A";
      return true;
    }

    if (!regex_search(command, matches, rgx)) {
      cout << printLeader() << "Unknown command" << endl;
      return false;
    }

    // Check what command
    if (matches[match_command] == "quit") {
      getEmulator().stop(name);
    }

    else if (matches[match_command] == "s") {
      if (matches[match_repeat].length() != 0) {
        size_t repeat = stol(matches[match_repeat]);
        if (repeat > 0) {
          skipnext = repeat - 1;
        } else {
          cout << "How would that repeat value even be possible?" << endl;
          return false;
        }
      }
    }

    else if (matches[match_command] == "c") {
      string address_str = matches[match_address];
      if (address_str.length() != 0) {
        armaddr_t until_address = (armaddr_t)strtol(address_str.c_str(), NULL, 0);
        if (until_address == 0) {
          cout << "Please enter a valid stop address (or no address)" << endl;
          return false;
        }
        setStopAddress(until_address);
      } else {
        setStopAddress(0);
      }
      cout << "Continuing until address: " << stopaddress << endl;
    }

    else if (matches[match_command] == "r") {
      cout << "Registers: " << endl;
      getEmulator().getRegisters().dump(cout);
      return false;
    }

		else if (matches[match_command] == "m") {
      armaddr_t address, length;
      string address_str = matches[match_address];
      string length_str = matches[match_length];
      if (address_str.length() == 0) {
        cout << "Please enter a valid memory address" << endl;
        return false;
      }

      address = (armaddr_t)strtol(address_str.c_str(), NULL, 0);
      length = (armaddr_t)strtol(length_str.c_str(), NULL, 0);

      if (length == 0) {
        cout << "Please enter a valid length to read" << endl;
        return false;
      }
      // Print the memory
      char *print_memory = new char [length];
      bool suc = getEmulator().readMemory(address, print_memory, length);
      if (suc == false) {
        cout << "Failed to read memory" << endl;
        delete[] print_memory;
        return false;
      }
      std::ios_base::fmtflags f(cout.flags());
      if (length%4 == 0) {
        for (armaddr_t i=0; i<length; i+=4) {
          uint32_t b0, b1, b2, b3;
          b0 = (unsigned char)print_memory[i];
          b1 = (unsigned char)print_memory[i+1];
          b2 = (unsigned char)print_memory[i+2];
          b3 = (unsigned char)print_memory[i+3];
          uint32_t memval = ((b3 << 24)&0xFF000000) | ((b2 << 16)&0xFF0000) | ((b1 << 8)&0xFF00) | (b0&0xFF);
          cout << hex << address+i << ":\t" << hex << memval << endl;
        }
      } else {
        for (armaddr_t i=0; i<length; i++) {
          cout << hex << address+i << ":\t" << hex << (unsigned int)print_memory[i] << endl;
        }
      }
      cout.flags(f);
      delete[] print_memory;
    }

    return false;
  }

  // Hook run
  void run(hook_arg_t *arg) {
    while (StepInstruction(arg->address) == false);
  }
};

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  HM.add(new StepInstructions(emu));
}

// Class that is used by ICEmu to finf the register function
// NB.  * MUST BE NAMED "RegisterMyHook"
//      * MUST BE global
RegisterHook RegisterMyHook(registerMyCodeHook);
