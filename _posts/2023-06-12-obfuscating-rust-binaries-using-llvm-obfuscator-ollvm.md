---
title: Obfuscating Rust Binaries using LLVM Obfuscator (OLLVM)
author: vrls
date: 2023-06-12
#categories: [TOP_CATEGORIE, SUB_CATEGORIE]
tags: [rust, obfuscation, llvm, ollvm, rustc, compiler, toolchain, reverse, engineering, reversing, protection, security]
image: /assets/img/posts/2023/06/bbd2d694438b7b8d063e372b3495b2616e0c812a90a0d6980c2f4b4c3d9e8cb9.png #og:image
permalink: /posts/2023/06/obfuscating-rust-binaries-using-llvm-obfuscator-ollvm/
description: Delve into obfuscation techniques for Rust binaries using LLVM Obfuscator (OLLVM) to enhance code protection against reverse engineering. Key tips on implementation, effectiveness, and trade-offs for developers securing their applications.
#image:
#  src: /assets/img/posts/YYYY/MM/MD5SUMHASH.png
#  width: 350   # in pixels
#  height: 350   # in pixels
---

<!-- ![image](/assets/img/posts/2023/06/bbd2d694438b7b8d063e372b3495b2616e0c812a90a0d6980c2f4b4c3d9e8cb9.png) 

<meta name="twitter:card" content="summary_large_image">
<meta property="twitter:domain" content="vrls.ws">
<meta property="twitter:url" content="https://vrls.ws/posts/2023/06/obfuscating-rust-binaries-using-llvm-obfuscator-ollvm/">
<meta name="twitter:title" content="Obfuscating Rust Binaries using LLVM Obfuscator (OLLVM)">
<meta name="twitter:description" content="Personal blog about computer hacking & security">
<meta name="twitter:image" content="https://vrls.ws/assets/img/posts/2023/06/bbd2d694438b7b8d063e372b3495b2616e0c812a90a0d6980c2f4b4c3d9e8cb9.png">

-->

## **UPDATE - 30 November 2023**

I have made available a Docker image containing all the required steps to build a Rust toolchain using OLLVM. Currently it is targeting both `x86_64-unknown-linux-gnu` and `x86_64-pc-windows-gnu` but haven't tested yet. At least it works for "hello world" programs.

Source: [https://github.com/joaovarelas/Obfuscator-LLVM-16.0](https://github.com/joaovarelas/Obfuscator-LLVM-16.0)

NOTE: You are going to need at least **30GB** of disk space and patience to compile LLVM 16.


1. `git clone https://github.com/joaovarelas/Obfuscator-LLVM-16.0 && cd Obfuscator-LLVM-16.0`
2. `docker build -t rustc-ollvm .`
3. `docker run -v /path/to/my/cargo/projects:/projects/ -it rustc-ollvm:latest /bin/bash`

Then inside the container:

4. `cd /projects/myproject/`
5. `RUSTCFLAGS="-Cllvm-args=-enable-allobf" cargo +ollvm-rust-1.70.0 build --release`

The executables will be placed at `target/`.

Credits to original author [https://bbs.kanxue.com/thread-274453.htm](https://bbs.kanxue.com/thread-274453.htm).


## Introduction


Reverse engineering is the process of analyzing and examinating a product or system to understand their inner workings, extract sensitive information, or modify their behavior. However, Rust compiled binaries present unique challenges due to its design and complexity.

Rust utilizes LLVM (Low-Level Virtual Machine) as its backend compiler infrastructure, which provides powerful optimization and code generation capabilities, enabling efficient execution of Rust code across different platforms and architectures. By leveraging LLVM's custom passes (such as the Obfuscator LLVM) can further enhance the obfuscation of Rust binaries, making them even more difficult to analyze and reverse engineer.

Complex malware can be a nightmare for analysts and incident responders as it requires a lot of time to examine, which can be critical when responding to an incident. Red teamers on the other side might gain an advantage against blue teams by protecting their tools (e.g. C2 beacon) both to evade antimalware solutions and difficult analysts job while performing adversary emulation or intrusion testing. 



## (De)compiling "Hello World"

Rust `cargo` is the package manager and build tool for the Rust programming language. It simplifies the process of managing dependencies, building projects, and running tests. With `cargo`, developers can easily create, share, and publish their Rust libraries and applications.



```bash
$ rustc --version --verbose
rustc 1.71.0-nightly (4a59ba4d5 2023-05-12)

$ cargo --version --verbose
cargo 1.71.0-nightly (13413c64f 2023-05-10)
```


### Default Configuration


As an example, the following `hello.rs` program will be compiled using a nightly version 1.71.0 [[1]](#references) at the moment of writing. A nightly toolchain may be installed using the `rustup` installer. 


```rust
pub fn main(){
	println!("hello world");
}
```


```bash
$ rustc hello.rs -o hello

$ ls hello
-rwxr-xr-x 1 vrls vrls 4.1M Jun 13 20:17 hello

$ file hello
hello: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7d399b3[...]817e24d9a, 
for GNU/Linux 3.2.0, with debug_info, not stripped

```


A compiled hello world ELF program using the default configuration is approximately 4.1MB, not stripped and contains debug info. The disassembly and pseudo code looks like the following, which is not that bad since we can easily follow the code and understand the logic (considering the simplicity of the code):


![image](/assets/img/posts/2023/06/67fef1c58c27c424fb4339e96ad8cad7599b0ff9aa62647fadca41be297ad237.png)



### Stripped Release

Now adjusting the compiler settings will make the produced executable a little harder to understand since there will be no debug info. This setting is ideal to use on production environment and released binaries. 

The `rustc` codegen options [[2]](#references) `-Cdebuginfo=0 -Cstrip=symbols -Cpanic=abort -Coptlevel=3` optimize the compilation process by excluding debugging information and symbol tables, resulting in a smaller binary. The `panic=abort` flag ensures immediate program termination upon encountering a panic, without unwinding the stack.

```bash

$ rustc -Cdebuginfo=0 -Cstrip=symbols -Cpanic=abort -Copt-level=3 hello.rs -o hello-stripped

$ ls hello*
-rwxr-xr-x 1 vrls vrls 4.1M Jun 13 20:17 hello
-rwxr-xr-x 1 vrls vrls 331K Jun 13 20:18 hello-stripped


$ file hello*
hello: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, 
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7d399b3[...]817e24d9a, for GNU/Linux 3.2.0, 
with debug_info, not stripped

hello-stripped: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, 
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f786e67[....]6706ec0b2d, 
for GNU/Linux 3.2.0, stripped

```


The resulting binary is slightly different when compared with the previous. There are a lot of other configurations that can be leveraged to optimize the resulting binary.


![image](/assets/img/posts/2023/06/df9a941de2f756ba2c794c8b7842e576e4ca3357219dc0e5099b34ae0a67605a.png)





## Obfuscator LLVM


LLVM Obfuscator [[3]](#references) is a modified version of LLVM that applies transformations to LLVM intermediate representation (IR) code in order to make it more difficult to understand and reverse engineer. By employing techniques like code obfuscation, control flow flattening, and variable substitution, LLVM Obfuscator aims to increase the complexity and confusion in the generated executable, enhancing the protection of the project and preventing unauthorized code analysis.

Given that Rust uses LLVM to generate MIR and LLVM-IR [[4]](#references), its possible to write custom optimization passes such as OLLVM that will transform the intermediate representation code generated by Rust.

![image](/assets/img/posts/2023/06/13f3c15df29747124c53fdf025f86fbd7ecb3e6238a8a0e52c4dd91a3474ecc4.png)


## Compiling OLLVM

Note that original OLLVM project [[3]](#references) is quite old and the latest version was built on top of LLVM 4.0 released more than 6 years ago. Currently the Rust-fork of LLVM is on version 16.0.2.

OLLVM forks may be found on open-source code repositories such as [[5, 6, 7 ,8]](#references). Interestingly enough, this project seems very common among chinese developers including native mobile apps developers and reverse engineers. Most of the custom passes found online have documentation in chinese language.

Additionaly OLLVM was referenced in game hacking communities used by players to protect their cheats and evade anti-cheat systems thus avoiding being banned from the game. For example, in `Unknown-Cheats` forum there is a guide [[9]](#references) on how to integrate OLLVM with Microsoft Visual Studio to aid cheat development and protection.

### Prerequisites

- Rust source-code: [https://github.com/rust-lang/rust](https://github.com/rust-lang/rust) (`1.70.0`)

- Rust LLVM fork source-code: [https://github.com/rust-lang/llvm-project](https://github.com/rust-lang/llvm-project) (`16.0.0-2023-03-06`)

- Fork of ObfuscatorLLVM (version should match Rust LLVM): 
	- Hikari-LLVM [[8]](#references) has branch for LLVM 16.0 and its compatible with current Rust versions. Feel free to implement your own passes.

- Build tools such as `cmake`, `Ninja`, `git`, `clang`, `python3` and so on

- Enough storage as the source will easily grow from 15GB to 20GB on disk


**NOTE:** This demo will focus on building a custom Rust OLLVM toolchain to obfuscate the binaries on Linux (ELF). The original article by `ny0c` [[10]](#references) is based on LLVM 14.0 and uses MSYS2 based on MinGW for Windows, have a look if you want to build Windows executables.



Start by cloning the required sources:


```bash
$ git clone --single-branch --branch 1.70.0 --depth 1 https://github.com/rust-lang/rust rust-1.70.0
$ git clone --single-branch --branch rustc/16.0-2023-03-06 --depth 1 https://github.com/rust-lang/llvm-project llvm-16.0-2023-03-06
$ git clone --single-branch --branch llvm-16.0.0rel --recursive --depth 1 https://github.com/61bcdefg/Hikari-LLVM15 ollvm-16.0
```

We want to add obfuscation passes into the Rust LLVM fork to make it compatible with compiler. By doing a `diff` it's trivial to compare which files are different and then apply a patch without damaging the original source.


```bash
$ git diff llvm-16.0-2023-03-06/llvm ollvm-16.0/llvm/ > llvm.patch
```


Output from `diff` will include a lot of tests and unit-test files that are not really interesting so we might manually remove them. Once we get a cleared version of the `diff` we can use it to patch the Rust LLVM fork with the Obfuscation module from OLLVM. The ideia is to apply the OLLVM patch with minimal modification of Rust LLVM to avoid incompatibility, dependency problems or bugs.


In resume, the important modifications to apply from the OLLVM on Rust LLVM fork are the following:


```bash 
$ cat llvm.patch | grep -iE "^diff " | grep -ivE "/llvm/test/|/llvm/utils/lit/tests/|/llvm/unittests/" | cut -d '/' -f 3-  | cut -d ' ' -f 1

llvm/include/llvm/InitializePasses.h
llvm/include/llvm/LinkAllPasses.h
llvm/include/llvm/MC/MCSubtargetInfo.h
llvm/include/llvm/Transforms/Obfuscation/[...]
llvm/lib/IR/AutoUpgrade.cpp (*)
llvm/lib/Passes/PassBuilderPipelines.cpp
llvm/lib/Support/Unix/Path.inc (*)
llvm/lib/Target/X86/X86ISelLowering.cpp
llvm/lib/Target/X86/X86InstrSSE.td (*)
llvm/lib/Transforms/CMakeLists.txt
llvm/lib/Transforms/IPO/CMakeLists.txt
llvm/lib/Transforms/IPO/PassManagerBuilder.cpp
llvm/lib/Transforms/InstCombine/InstCombineCompares.cpp (**)
llvm/lib/Transforms/Obfuscation/[...]
llvm/tools/xcode-toolchain/CMakeLists.txt
```

- (*) should not be patched and remain the same as Rust LLVM
- (**) should be partially patched by adding lines, but not removing existing ones   


![image](/assets/img/posts/2023/06/253b0d9d56ba356c7fdaaf4dd8169ff2972b68a19920308b66ff85bd0f7c212a.png)



Finally apply the patch and fix any error that may occur by looking for `*.rej` files, they are automatically created when conflicts are detected. 


```bash
$ cd llvm-16.0-2023-03-06/
$ git apply --reject --ignore-whitespace ../llvm.patch
$ find . -name "*.rej" # no output, means we are good
```



### Building


```bash
$ cd llvm-16.0-2023-03-06/
$ mkdir build && cd build/
$ cmake -G "Ninja" ../llvm -DCMAKE_INSTALL_PREFIX="./llvm_x64" -DCMAKE_CXX_STANDARD=17 \
  -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_PROJECTS="clang;lld;" -DLLVM_TARGETS_TO_BUILD="X86" \
  -DBUILD_SHARED_LIBS=ON -DLLVM_INSTALL_UTILS=ON -DLLVM_INCLUDE_TESTS=OFF -DLLVM_BUILD_TESTS=OFF \
  -DLLVM_INCLUDE_BENCHMARKS=OFF -DLLVM_BUILD_BENCHMARKS=OFF -DLLVM_INCLUDE_EXAMPLES=OFF \
  -DLLVM_ENABLE_BACKTRACES=OFF -DLLVM_BUILD_DOCS=OFF  -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_CXX_COMPILER=clang++-16 -DCMAKE_C_COMPILER=clang-16
```

![image](/assets/img/posts/2023/06/92e31f13280f4278027085d7ff1bc964ee55c5afc6ec45d9bd69c73025aaee19.png)



```bash
$ cmake --build . -j8 # will take some time depending on hardware... go grab a redbull
$ cmake --install .
```


Once its built and installed we can check if the binaries are working as expected. In this case, it was installed inside the `build/` directory inside the `llvm_x64` as specified previously by `-DCMAKE_INSTALL_PREFIX`.

Note that install location will be used in the future by `rustc` to use our custom LLVM infrastructure.


```bash
$ ./llvm_x64/bin/llvm-config  --version
16.0.0

$ ./llvm_x64/bin/clang --version
clang version 16.0.0 (https://github.com/rust-lang/llvm-project 2b9c52f66815bb8d6ea74a4b26df3410602be9b0)
Target: x86_64-unknown-linux-gnu
Thread model: posix
InstalledDir: /mnt/VMs/ollvm/llvm-16.0-2023-03-06/build/./llvm_x64/bin
```

Verify that `build/llvm_x64/lib/` directory contains `*.a` static lib files, in particular `libLLVMObfuscation.a`. Also, save the *absolute* path for `build/llvm_x64/bin/llvm-config` as it will be needed next.


## Bootstrapping Rust Compiler

Having the OLLVM ready, it's time to move into Rust compiler. Rust compiler bootstrapping involves building the compiler using another language (e.g. C) and then using the compiler to compile a self-hosted version, resulting in a final Rust compiler.

This process consists of 3 stages:

- Stage 0: an initial version of the Rust compiler is built using Rust - initially OCaml was used [[11]](#references).
- Stage 1: the compiler from Stage 0 is used to compile a self-hosted version of the compiler.
- Stage 2: the self-hosted compiler is used to compile the final version of the Rust compiler, which can be used for further development.


![image](/assets/img/posts/2023/06/ea363238f367d974708abb3edff769d63898c08bb27eb07e803b203e3ac00add.png)


Before starting the build of Rust compiler, we should adjust `config.toml` file to specify the modified LLVM we just built. This can be defined by setting `llvm-config = /path/to/llvm-config`. 

1. Copy `config.example.toml`to `config.toml`
2. Edit `config.toml`
3. In `[rust]` section, set `debug = false`
4. In `[rust]` section, set `channel = "nightly"`
5. In `[target.x86_64-unknown-linux-gnu]` section, set `llvm-config = "/path/to/ollvm/bin/llvm-config"`
	- If you are targeting a different system, make sure to rename section `[target.x86_64-unknown-linux-gnu]` to `[target.x86_64-pc-windows-gnu]` for example.


![image](/assets/img/posts/2023/06/dc3e67e163f7e107631caa97b9a65f58e98a752704ec780b2d15a26827816a0b.png)



Once the configuration is done, it's time to build the Rust compiler. Currently Rust provides a build script named `x.py` that simplifies the process of bootstrapping. 
To build just execute:


```bash
$ cd rust-1.70.0/
$ python3 x.py build # will take some time... 
```

![image](/assets/img/posts/2023/06/dd145db803fc4b6977633f0c18364d5347a3293361ced7eacbb95471fa29bfc9.png)

Observe that during assembly of `stage1` compiler will already make use of OLLVM (however with obfuscation flags disabled, as they are not needed at this point yet). Once finished, check if `rustc` was successfully compiled:

```bash
$ ./build/x86_64-unknown-linux-gnu/stage1/bin/rustc --version --verbose

rustc 1.70.0-nightly (90c541806 2023-05-31)
binary: rustc
commit-hash: 90c541806f23a127002de5b4038be731ba1458ca
commit-date: 2023-05-31
host: x86_64-unknown-linux-gnu
release: 1.70.0-nightly
LLVM version: 16.0.0
```


Finally, the `cargo` must be built too. This can be accomplished by using the `x.py` tool once again:


```bash
$ python3 x.py build tools/cargo
$ ./build/x86_64-unknown-linux-gnu/stage1-tools-bin/cargo --version
cargo 1.70.0-nightly (ec8a8a0ca 2023-04-25)
```




## Add Custom Toolchain


The `rustc` and `cargo` can be added as a custom toolchain to the Rust setup. The toolchain allows to easily switch between different versions of Rust when developing projects.

```bash 
$ rustup toolchain list
stable-x86_64-pc-windows-gnu
stable-x86_64-unknown-linux-gnu
nightly-x86_64-unknown-linux-gnu (default)

$ rustup toolchain link ollvm-rust-1.70.0 /mnt/VMs/ollvm/rust-1.70.0/build/x86_64-unknown-linux-gnu/stage1/

$ rustup toolchain list
stable-x86_64-pc-windows-gnu
stable-x86_64-unknown-linux-gnu
nightly-x86_64-unknown-linux-gnu (default)
ollvm-rust-1.70.0 <---------------------------- the new toolchain
```

![image](/assets/img/posts/2023/06/797e74d3e43f5414149ea43deb643ebaf572a381dfbd01b36b52972dd300ad90.png)



## Results 

The fresh toolchain can now be selected to compile Rust programs through custom LLVM including obfuscation apsses. Unless it is set as default (using `rustup default ollvm-rust-1.70.0`) it must be specified when executing `rustc` or `cargo` by adding the format `+toolchain`.

Going back to the initial `hello.rs` example, lets recompile it using the new OLLVM toolchain:

```bash
$ rustc +ollvm-rust-1.70.0 hello.rs -o hello-ollvm
```

The command will work but none of the obfuscation techniques were enabled. Looking at the OLLVM passes configuration or Hikari documentation Wiki, we can find the available flags:


![image](/assets/img/posts/2023/06/19592b4cb226cf8d9e2dcb170b2ee1355a05183869acab20265373021e29594d.png)


Flags should be passed to LLVM. The Rust compiler allows to pass flags to LLVM via codegen `llvm-args` [[12]](#references).
For simplicy let's use `-enable-allobf` to enable all the features available:


```bash
$ rustc +ollvm-rust-1.70.0 -Cllvm-args=-enable-allobf hello.rs -o hello-ollvm

$ ls hello-ollvm 
-rwxr-xr-x 1 vrls vrls 482K Jun 15 21:23 hello-ollvm

$ file hello-ollvm 
hello-ollvm: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, 
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=4cbc70187af8[..]]2fe42ca921c4, 
for GNU/Linux 3.2.0, not stripped

$ ./hello-ollvm 
hello world
```

![image](/assets/img/posts/2023/06/96be37ba4e492b0484becb770b96097eec69055cebcd2aedc71c26b228b8d26b.png)


![image](/assets/img/posts/2023/06/420dd022e8c7e5bae584de1d6b6fb47cbd8af24b1796920d8b73b61ea295f967.png)


Symbols are still present on this executable since it was not compile on release mode and they may be removed by specifying additional compiler flags (stripped):



```bash
$ rustc +ollvm-rust-1.70.0 -Cllvm-args=-enable-allobf -Cdebuginfo=0 \
    -Cstrip=symbols -Cpanic=abort -Copt-level=3 hello.rs -o hello-ollvm-strip

$ ls hello-ollvm-strip 
-rwxr-xr-x 1 vrls vrls 367K Jun 15 21:25 hello-ollvm-strip

$ file hello-ollvm-strip 
hello-ollvm-strip: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, 
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ad38d6ff[...]]849e395, 
for GNU/Linux 3.2.0, stripped

$ ./hello-ollvm-strip
hello world
```


![image](/assets/img/posts/2023/06/193e39469268f5ea6ebd2b75c497908bca93d129536a1db12b5d88bc855686cf.png)


Resulting disassembly is now much harder to follow and requires additional attention when reversing this program. The simple "hello world" is now obfuscated and difficult to understand.

Example of `main` function of program compiled with default settings (debug info) VS. OLLVM stripped:

![image](/assets/img/posts/2023/06/a48f3490ef737d356ee912bdbb374c2f4df7d02c1c9bed940882e7827b0add4d.png)

![image](/assets/img/posts/2023/06/344b8b80ab2a95dce1c231bb7acf653a2d036d28b8519f5b13d8015b4baddf96.png)


## Conclusion

This approach describes how to integrate the known LLVM Obfuscator project into an updated Rust toolchain and allow developers to obfuscate and protect their software by applying known techniques such as control flow flattening, bogus control flow and string encryption and so on.

Additionally, it is a good baseline for those seeking to add their own custom passes (i.e. optimization methods) and introduce newer and better obfuscation techniques. Other languages besides Rust such as C/C++ (Clang), Golang and Swift also make use of LLVM infrastructure, giving the opportunity to use OLLVM between different programming languages and potentially cross-platform. Some other interesting projects also focus on code protection such as Rust `goldberg` [[13]](#references) and `obfstr` [[14]](#references). 

Modern obfuscation mechanisms include code virtualization used to protect software by transforming its code into a virtualized form and or bytecode that is executed by a virtual machine or interpreter. A proof-of-concept can be found at `xVMP` repository [[15]](#references). The respective paper is available at [[16]](#references) with the title `xVMP: An LLVM-based Code Virtualization Obfuscator` which improves current obfuscation methods based on LLVM.

From the other perspective, there has been a focus on finding better approaches to reverse Rust binaries. Essentially compiled programs on C/C++ and Rust have some similarities and differences considering the resulting binary executables. There is a really good article by Checkpoint Research [[17]](#references) that gives a solid overview on reversing Rust binaries.


## Source Code

Patch for Rust-LLVM is available on my repository: 
- [https://github.com/joaovarelas/Obfuscator-LLVM-16.0/](https://github.com/joaovarelas/Obfuscator-LLVM-16.0/) 

It should be manually applied when compiling LLVM and Rust thereafter. Feel free to reach out on Discord: `vrls` or open an issue on GitHub repo if you find any difficulty reproducing the steps.


## References

[1] [https://releases.rs/docs/1.71.0/](https://releases.rs/docs/1.71.0/){:target="_blank"}

[2] [https://doc.rust-lang.org/rustc/codegen-options/index.html](https://doc.rust-lang.org/rustc/codegen-options/index.html){:target="_blank"}

[3] [https://github.com/obfuscator-llvm/obfuscator](https://github.com/obfuscator-llvm/obfuscator){:target="_blank"}

[4] [https://dev.to/bexxmodd/llvm-infrastructure-and-rust-5g71](https://dev.to/bexxmodd/llvm-infrastructure-and-rust-5g71){:target="_blank"}

[5] [https://github.com/o2e/OLLVM-9.0.1](https://github.com/o2e/OLLVM-9.0.1){:target="_blank"}

[6] [https://github.com/heroims/obfuscator](https://github.com/heroims/obfuscator){:target="_blank"}

[7] [https://github.com/SsageParuders/SsagePass](https://github.com/SsageParuders/SsagePass){:target="_blank"}

[8] [https://github.com/61bcdefg/Hikari-LLVM15](https://github.com/61bcdefg/Hikari-LLVM15){:target="_blank"}

[9] [https://www.unknowncheats.me/forum/anti-cheat-bypass/500042-ollvm-13-llvm-obfuscator-vs2022-compatible.html](https://www.unknowncheats.me/forum/anti-cheat-bypass/500042-ollvm-13-llvm-obfuscator-vs2022-compatible.html){:target="_blank"}

[10] [https://bbs.kanxue.com/thread-274453.htm](https://bbs.kanxue.com/thread-274453.htm)

[11] [https://rustc-dev-guide.rust-lang.org/building/bootstrapping.html](https://rustc-dev-guide.rust-lang.org/building/bootstrapping.html)

[12] [https://doc.rust-lang.org/rustc/codegen-options/index.html#llvm-args](https://doc.rust-lang.org/rustc/codegen-options/index.html#llvm-args)

[13] [https://docs.rs/goldberg/latest/goldberg/index.html](https://docs.rs/goldberg/latest/goldberg/index.html)

[14] [https://github.com/CasualX/obfstr](https://github.com/CasualX/obfstr)

[15] [https://github.com/GANGE666/xVMP](https://github.com/GANGE666/xVMP)

[16] [https://ieeexplore.ieee.org/document/10123584/](https://ieeexplore.ieee.org/document/10123584/)

[17] [https://research.checkpoint.com/2023/rust-binary-analysis-feature-by-feature/](https://research.checkpoint.com/2023/rust-binary-analysis-feature-by-feature/)