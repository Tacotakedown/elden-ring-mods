# Building

## Requirements:

- Rust (cargo)
- MSVC or GCC

## Windows:

```bash
git clone https://github.com/Tacotakedown/elden-ring-mods && cd elden-ring-mods
./build.ps1
# follow the build script, built files will be built to ${ProjectDir}/${ModName}/target/release/${ModName}.dll
# simply load with mod_engine2
```

## Linux:

Make sure you have access to `Windows.h` and its dependencies on your distro

```bash
git clone https://github.com/Tacotakedown/elden-ring-mods && cd elden-ring-mods
./build.sh
# follow the build script, built files will be built to ${ProjectDir}/${ModName}/target/release/${ModName}.dll
# now get on Windows
# load with mod_engine2
```
