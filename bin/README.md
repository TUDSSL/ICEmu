## Wrapper script to make using ICEmu easier

It will try to find plugins without the full path.
It does require ICEmu to be compiled and in the ../build directory.

Default plugin paths are (relative to this directory):
```
../example-plugins
../plugins
```

Other paths can be added using the `ICEMU_PLUGIN_PATH` environment variable using
absolute paths separated by a colon e.g.,
```
export ICEMU_PLUGIN_PATH="/home/user/newpath/to/plugins:~/relative/to/home/is/ok:$ICEMU_PLUGIN_PATH"
```

