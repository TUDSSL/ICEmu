#include <iostream>

#include <capstone/capstone.h>
#include <unicorn/unicorn.h>

#include "icemu/emu/Memory.h"
#include "icemu/emu/Emulator.h"

using namespace std;
using namespace icemu;

bool Emulator::init() {
  if (bad()) {
    cerr << "Emulator not configured correctly" << endl;
    return false;
  }

  uc_err err;
  // Map all the memory
  for (const auto &m : mem_.memory) {
    // Unicorn requires the the lenght to be a multiple of 1024
    // This is done in the Memory class and set to allocated_length
    err = uc_mem_map_ptr(uc, m.origin, m.allocated_length, UC_PROT_ALL, m.data);
    if (err) {
      cerr << "Error mapping memory: " << m.name << " with error: " << err
           << " (" << uc_strerror(err) << ")" << endl;
      good_ = false;
      return false;
    }
  }

  return true;
}

bool Emulator::run() {
  if (bad()) {
    cerr << "Emulator not initialized correctly" << endl;
    return false;
  }

  armaddr_t sp = 0x1005fff8;
  uc_reg_write(uc, UC_ARM_REG_SP, &sp);

  uc_err err = uc_emu_start(uc, mem_.entrypoint | 1, 0xc154, 0, 0);
  if (err) {
    cerr << "Failed to start emulation with error: " << err << " ("
         << uc_strerror(err) << ")" << endl;
  }

  return true;
}
