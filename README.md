# b3typer

This is a JSC CTF challenge I made for bi0sCTF 2022, based on an incorrect range assumption in B3's Strength Reduction phase. A detailed write-up can be found [here](./writeup.md), challenge handout can be found [here](./src/b3typer_handout.zip), and the complete exploit [here](./src/exp.js).

## Build Instructions (Debug)

```sh
git clone https://github.com/WebKit/WebKit.git
cd WebKit
git checkout 645b9044d2369e3b083b171da517a2440bb4fa18
git apply debug.patch
Tools/gtk/install-dependencies
Tools/Scripts/build-webkit --jsc-only --debug
cd WebKitBuild/Debug/bin

./jsc --useConcurrentJIT=false
```

## Short Writeup

+ Simple typer bug, range of BitAnd opcode is assumed to be [1, operand] when in reality it is [0, operand].
+ Use range assumptions to create unchecked integer underflow.
+ Bypass array bounds checks and obtain OOB write, overwrite size of array to get overlap.
+ Use double & object array overlap to create addrOf & fakeObj primitives.
+ Create overlapping fake array using StructureID leak to obtain arbitrary R/W.