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

#include "RiscvXXRocketchipSyscall.h"

using namespace std;
using namespace icemu;

// Function that registers the hook
static void registerMyCodeHook(Emulator &emu, HookManager &HM) {
  auto p = new RiscvXXRocketchipSyscall<uint64_t>(emu);
  if (p->good) {
    HM.add(p);
  } else {
    delete p;
  }
}

// Class that is used by ICEmu to finf the register function
// NB.  * MUST BE NAMED "RegisterMyHook"
//      * MUST BE global
RegisterHook RegisterMyHook(registerMyCodeHook);
