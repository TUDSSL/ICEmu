#include <iostream>

#include <capstone/capstone.h>
#include <unicorn/unicorn.h>

#include "icemu/emu/Memory.h"
#include "icemu/emu/Emulator.h"
#include "icemu/hooks/HookManager.h"

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

  // Setup all the hooks
  registerHooks();

  return true;
}

bool Emulator::run() {
  if (bad()) {
    cerr << "Emulator not initialized correctly" << endl;
    return false;
  }

  // Initialize the hooks
  registerHooks();

  // Multiple TODO for this one:
  //  - Make the symbol configurable
  //  - Make the memory mapping such that it can cope with the vector table (at
  //    address 0x0 (currently unmapped, not sure how to infer stuff like this
  //    generically)
  //  - Then fix (read restore) the `startup_gcc.c` code in a way that sets the
  //    SP without having to manually specify it.
  try {
    armaddr_t sp = getMemory().symbols.get("_estack")->address;
    uc_reg_write(uc, UC_ARM_REG_SP, &sp);
  } catch (const std::out_of_range &e) {
    cerr << "Failed to find the address of symbol: _estack" << endl;
    return false;
  }

  uc_err err = uc_emu_start(uc, mem_.entrypoint | 1, 0xc154, 0, 0);
  if (err) {
    cerr << "Failed to start emulation with error: " << err << " ("
         << uc_strerror(err) << ")" << endl;
  }

  return true;
}

static void hook_code_cb(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
  (void)uc; // This should be known

  // The Emulator * is the user_data
  Emulator *emu = (Emulator *)user_data;
  HookManager &hook_manager = emu->getHookManager();

  // Build the argument struct
  HookCode::hook_arg_t arg;
  arg.address = (armaddr_t)address;
  arg.size = (armaddr_t)size;

  hook_manager.run(address, &arg);
}

static void hook_memory_cb(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
  (void)uc; // This should be known

  // The Emulator * is the user_data
  Emulator *emu = (Emulator *)user_data;
  HookManager &hook_manager = emu->getHookManager();

  // Build the argument struct
  HookMemory::hook_arg_t arg;
  arg.address = (armaddr_t)address;
  arg.size = (armaddr_t)size;
  arg.value = (armaddr_t)value;

  switch (type) {
    case UC_MEM_READ:
      arg.mem_type = HookMemory::MEM_READ;
      break;
    case UC_MEM_WRITE:
      arg.mem_type = HookMemory::MEM_WRITE;
      break;
    default:
      // TODO Handle the other cases
      // For now we call a message and never run the hooks.
      // Probably want to add these types to out memory class and just map them
      // and let plugins/hooks deal with them
      cerr << "Experienced unmpapped read or write, not implemented" << endl;
      return;
  }

  hook_manager.run(address, &arg);
}

bool Emulator::registerCodeHook() {

  // If begin > end the hook is always called
  const uint64_t range_code_begin = 1;
  const uint64_t range_code_end = 0;

  uc_hook_add(uc, &uc_hook_code, UC_HOOK_CODE, (void *)&hook_code_cb,
              (void *)this, range_code_begin, range_code_end);

  return true; // TODO
}

bool Emulator::registerMemoryHook() {

  // If begin > end the hook is always called
  const uint64_t range_memory_begin = 1;
  const uint64_t range_memory_end = 0;

  // We want to hook READ and WRITE and figure it out later
  uc_hook_add(uc, &uc_hook_memory, UC_HOOK_MEM_READ, (void *)&hook_memory_cb,
              (void *)this, range_memory_begin, range_memory_end);

  uc_hook_add(uc, &uc_hook_memory, UC_HOOK_MEM_WRITE, (void *)&hook_memory_cb,
              (void *)this, range_memory_begin, range_memory_end);

  return true; // TODO
}

bool Emulator::registerHooks() {

  registerCodeHook();
  registerMemoryHook();

  return true;
}

void Emulator::stop(string reason) {
  cout << "Stopping the emulator, reason: " << reason << endl;
  uc_err err = uc_emu_stop(uc);

  if (err != UC_ERR_OK) {
    cerr << "Failed to stop the emulator" << endl;
  }
}

// TODO: Should probably make a "C++" version using a vector or something
bool Emulator::readMemory(armaddr_t address, char *result, armaddr_t size)
{
  uc_err err = uc_mem_read(uc, address, result, size);
  if (err != UC_ERR_OK) {
    cerr << "Failed to read memory at address: " << address << " size: " << size
         << endl;
    return false;
  }
  return true;
}

