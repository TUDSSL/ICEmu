#pragma once
/**
 *  ICEmu loadable plugin (library)
 *
 *  Parses the tohost syscall message from rocketchip
 *

    #define SYS_write 64

    extern volatile uint64_t tohost;
    extern volatile uint64_t fromhost;

    static uintptr_t syscall(uintptr_t which, uint64_t arg0, uint64_t arg1, uint64_t arg2)
    {
      volatile uint64_t magic_mem[8] __attribute__((aligned(64)));
      magic_mem[0] = which;
      magic_mem[1] = arg0;
      magic_mem[2] = arg1;
      magic_mem[3] = arg2;
      __sync_synchronize();
    
      tohost = (uintptr_t)magic_mem;
      while (fromhost == 0)
        ;
      fromhost = 0;
  
      __sync_synchronize();
      return magic_mem[0];
    }

    void printstr(const char* s)
    {
      syscall(SYS_write, 1, (uintptr_t)s, strlen(s));
    }
 */
#include <iostream>
#include <string.h>

#include "icemu/emu/Emulator.h"
#include "icemu/hooks/HookFunction.h"
#include "icemu/hooks/HookManager.h"
#include "icemu/hooks/RegisterHook.h"

#include "PluginArgumentParsing.h"

/*
 * Select 64 bit or 32 bit
 */
template <class T>
class RiscvXXRocketchipSyscall : public icemu::HookMemory {
 public:
  typedef T sys_t;

 private:
  const icemu::symbol_t *to_host;
  const icemu::symbol_t *from_host;

  char *mem_to_host;
  char *mem_from_host;

  const T SYS_write = 64;

  std::string printLeader() {
    return "[syscall] ";
  }

  std::string color_start = "\033[1m";
  std::string color_end = "\033[0m";

  std::string output_file;
  std::ofstream output_file_stream;

 public:
  bool good = true;
  RiscvXXRocketchipSyscall(icemu::Emulator &emu) : HookMemory(emu, "syscall") {
    // Get where to store the log file (if any)
    auto name_arg = PluginArgumentParsing::GetArguments(emu, "syscall-print-logfile=");
    if (name_arg.size()) {
      output_file = name_arg[0];

      // Open the output file
      output_file_stream.open(output_file, std::ios::out);
      std::cout << printLeader() << " writing output to: " << output_file << std::endl;
    }

    // Setup the hook
    icemu::Symbols &sym = getEmulator().getMemory().getSymbols();

    to_host = sym.get("tohost");
    from_host = sym.get("fromhost");

    if (to_host == nullptr) {
      std::cerr << printLeader() << "was not able to resolve symbol 'tohost'" << std::endl;
      good = false;
      return;
    }
    if (from_host == nullptr) {
      std::cerr << printLeader() << "was not able to resolve symbol 'fromhost'" << std::endl;
      good = false;
      return;
    }

    // Get the pointer to the emulator memoroy
    mem_to_host = getEmulator().getMemory().at(to_host->address);
    mem_from_host = getEmulator().getMemory().at(from_host->address);

  }

  ~RiscvXXRocketchipSyscall() {
    std::cout << color_end;
    if (output_file_stream.is_open()) output_file_stream.close();
  }

  // Hook run (at every memory access)
  void run(hook_arg_t *arg) {
    address_t addr = arg->address;
    if ((addr == to_host->address) && (arg->mem_type == MEM_WRITE)) {

      // Read the arguments
      sys_t magic_mem[8];

      // Memory write did not yet happen, but is being written
      sys_t magic_mem_address = arg->value;
      char *host_magic_mem_address = getEmulator().getMemory().at(magic_mem_address);

      // Copy the magic mem (we don't know if we can access it on the host directly due to allignment)
      memcpy(magic_mem, host_magic_mem_address, sizeof(magic_mem));

      // Get the fields (from syscall)
      sys_t which = magic_mem[0];
      sys_t arg0 = magic_mem[1];
      sys_t arg1 = magic_mem[2];
      sys_t arg2 = magic_mem[3];

      if (which == SYS_write && arg0 == 1) {
        // For printing
        sys_t buffer_addr = arg1;
        sys_t buffer_len = arg2; // size of string without the '\0'

        char *buffer_host_addr = getEmulator().getMemory().at(buffer_addr);
        std::cout << color_start;
        for (size_t i=0; i<buffer_len; i++) {
          char c = buffer_host_addr[i];
          std::cout << c;
          if (output_file_stream.is_open()) {
            output_file_stream << c;
          }
        }
        std::cout << color_end;
      }

      // Set the from_host to 1 signalling that the syscall can continue
      // *mem_from_host = 1;
    }
  }
};
