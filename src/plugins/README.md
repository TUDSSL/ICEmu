# One line plugin descriptions

These plugins are intended for internal use and will probably be moved somewhere
else at one point.

```
call_count_plugin/
  Counts the number of times specified functions are called.
  arguments:
    call-count-track=<function_to_track> (can be passed multiple times)
    call-count-file=<file_to_store_results>

call_frequency_plugin/
  Keeps track of the frequency of calls in cycles. i.e. the number of cycles
  between *any* of the functions specified.
  arguments:
    call-frequency-track=<function_to_track> (can be passed multiple times)
    call-frequency-file=<file_to_store_results>

callsite_count_plugin/
  Tracks the *callsite* and the number of times specified functions are called
  arguments:
    callsite-count-track=<function_to_track> (can be passed multiple times)
    callsite-count-file=<file_to_store_results>

checkpoint_marker_plugin/
  Legacy, tracks special marker functions

checkpoint_side_effects_plugin/
  Checks if a checkpoint does not alter the register content and checks if a
  restore restores all the registers correctly (no side effects). Is used in
  combination with a special checkpoint test (not normal code).

checkpoint_verification_plugin/
  Checks if all WAR violations where handled by the placed checkpoints. This
  is used to verify if the checkpoints where correctly placed in the code.

cycle_count_plugin/
  Attempts to emulate the ARM cortex m-? pipeline

display_instructions_plugin/
  Prints the instructions that is about to be executed

final_value_plugin/
  Prints the final value of a variable in memory (only global variables)

idempotency_statistics_plugin/
  Legacy, used to check idempotent region size without any checkpoints

instruction_count_main_plugin/
  Counts the number of instructions executed after entering the 'main' function

instruction_profiling_plugin/
  Stores for each instruction in the program how many times it has been
  executed. This is used in a seperate visualization program to identify
  hotspots.

intermittency_plugin/
  Legacy intermittency plugin that tries to reset the system after every
  instruction.

memory_access_ratio_plugin/
  Print the ratio between read and writes to regions in memory

mock_clockfunc_emutime_plugin/
  Supports the clockfunc in the CoreMark benchmark using the actual
  emulation time.

mock_clockfunc_plugin/
  Supports the clockfunc in the CoreMark benchmark using the number of
  clock cycles.

mock_putc_plugin/
  Hooks the putc function to print text (instead of for example UART)

powertrace_plugin/
  Execute code with specific power traces to test intermittent execution

step_instructions_plugin/
  Step through each instruction of the code (and some basic 'run untill'
  features) used to debug code.

track_variable_plugin/
  Track the accesses to a global variable
```
