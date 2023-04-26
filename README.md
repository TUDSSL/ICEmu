# ICEmu
Intermittent Computing Emulator

## Building ICEmu
1. Checkout ICEmu
2. Update all the sumbmodules: `git submodule update --init --recursive`
3. Setup the common libraries:
`./setup-lib.sh`
4. (optionally) Build arm code:
`./arm-code/build-gcc.sh` (or `build-clang.sh` if applicable)
5. Run an elf binary in ICEmu (the memory layout in the config file must
   correspond to that of the device the .elf is created for).

## Usage
You can either use the ICEmu binary directly, or use the wrapper script
[`bin/icemu`](bin/) to make running it easier.


### Using the ICEmu binary directly
```
ICEmu ARM Emulator
Usage: ICEmu [options] program.elf
Allowed options:
  -h [ --help ]              produce help message
  -c [ --config-file ] arg   json config file
  -e [ --elf-file ] arg      elf input file
  -p [ --plugin ] arg        load plugin (can be passed multiple times)
  -x [ --dump-hex ]          dump hex file of the memory regions at completion
  -b [ --dump-bin ]          dump bin file of the memory regions at completion
  -r [ --dump-reg ]          dump file with the register values at completion
  --dump-prefix arg (=dump-) dump file prefix
```

### Using the icemu wrapper script
All options that do not relate to the wrapper (listed below) are passed directly
to the ICEmu binary (above). The wrapper helps you by:
* Searching default plugin directories, so no full path is needed.
* Searching default config directories, so no full path is needed.
* Selecting a default configuration if no configuration is provided.

run `icemu --wrapper-info` for more details and check the wrapper
[README](bin/README.md).

```
Usage: icemu [options] program.elf
ICEmu wrapper script options:
  --help-wrapper        produce this wrapper help message
  --wrapper-info        print wrapper info and options
  --wrapper-plugins     print all found plugins
  --wrapper-configs     print all found config files
```

### Demo
![](doc/gif/icemu-build.gif)
