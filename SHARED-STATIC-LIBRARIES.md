<h1 align="center">Shared/Static libraries</h1>
<ul>
  <li>Libraries generically are just files with certain declarations, functions that could be used further for any user that gets his hands on the particular library, therefore it's just a file</li>
  <li>When we write a program, there's different stages of preparation till the file can be considered an executable file</li>
  <li>.so = shared, .a = static</li>
  <li>Static linking = depends on the linker but some could copy and paste all of the code (text of the function) in our .elf file, some could just copy and paste just all the dependencies, nonetheless the actual size of the .elf file will be larger in size</li>
  <li>Shared linking = loader will look at GOT table and map the needed memory TO THE VIRTUAL SPACE OF THE PROCESS, thus making the size of the ELF file comparably smaller than static linking, after the first resolution of the GOT table it is in the virtual memory of the file and therefore another resolution of the same function won't be needed with the GOT table</li>
  <li>In a nutshell, the linker (ld) does STATIC linking (copying and pasting the function the program needs) and the loader does the run-time DYNAMIC LINKING (from environment variables, default settings, rpath), but beware there are many types of loaders, for example a loader that actually LOADS the file into memory and sets ups the virtual memory, reallocation, etc. AND there's the other loader which LOADS the needed functions into the pre-loaded virtual memory of the process</li>
  <li>although this could be different on different types of systems as stated here https://unix.stackexchange.com/questions/50335/unix-linux-loader-process it says, that there is a linker ld which statically links the libraries AND another linker/loader ld.so/ld-linux.so is actually doing a job of linking and finding the needed references and also loading them into the virtual memory of the process</li>
  <li>.elf, .so CAN be executed, there just has to be an entry point (main function or whatever function we specify), everything that has the ELF header can be executed</li>
</ul>
<h2>Specifing the commands to a compiler</h2>
<ul>
  <li>-L /path is the argument for the STATIC linker to look for files (static objects - linker/loader) on where to find them</li>
  <li>-I /path is the argument for the STATIC linker to look for files (header file, source code files - linker/loader) on where to find them, ALSO it is needed to specify the NAME of the library as -llibrary_name => -l for library (lib) and library_name as the library name, so for libevent => -levent, libssl => -lssl</li>
  <li>more info about actually putting commands for the linker and loader here https://medium.com/@abhishekjainindore24/linker-flags-its-options-1119ff6fa7f9</li>
  <li>ld.so/ld-linux.so = runtime linker/dynamic loader => linker/loader</li>
</ul>
<h2>Stages of a file becoming an executable</h2>
<ul>
  <li>As previously mentioned, there are certain stages which all files (that need to be executed) need to go through before becoming an actual executable program</li>
  <li>Preprocessor, Compiler, Assembler, Linker</li>
</ul>
<h3>Preprocessor</h3>
<ul>
  <li>Preprocessor is a computer program which takes in some input file and outputs the same file with certain modifications</li>
  <li>What I mean by modifications is, in C there is preprocessor features that allow us to for example include different kinds of header file based on the architecture/OS we are running our program on, also when we want to use some explicit flags for compiler or enable a specific standard of C</li>
  <li>Also preprocessor is great for defining macros</li>
  <li>Preprocessor takes out .c file with all of those macros or conditional includes and actually rewrites out code in such a way based on which if statements we used (preprocessor) or takes our functions written like macros and actually applies it to the code</li>
  <li>Preprocessor is built in compilers</li>
  <li>Preprocessor -> Compilator</li>
  <li>C = .i, C++ = .ii</li>
</ul>

<h3>Compiler</h3>
<li>Compiler takes the rewritten code a turns it into an intermediate file (what I mean by intermediate, C C++ compilers turn .i into an assembly file .s, which basically just means it turns it into assembly language (.i -> .s) but Java compilers turn .java into Java bytecode)</li>
<li>The .s file contains instructions for the CPU in assembly language</li>

<h3>Assembler</h3>
<ul>
  <li>Assembler is internally called to the temporary .s file to turn it into a .o file</li>
  <li>Object (.o) file is just a machine language (zeroes and ones), therefore this is great if we want to embed some binary code for rpath - runtime library search path for the next step (linker embeds this information for loader to find the exact dynamic libraries)</li>
  <li>.s -> .o</li>
</ul>

<h3>Linker</h3>
<ul>
  <li>Linker is a program that takes the .o file and finds and links the functions in our C code to the definitions, declarations etc., it finds those function implicitly for some libraries (standard libraries) but for some others, -L, -I needs to be used</li>
  <li>Linker is the final step of turning the .c into .elf file (executable file), there's another program though which is needed for runtime dynamic searching libraries, loading the executable into memory...this program is called a loader</li>
  <li>.o -> .elf</li>
</ul>
https://medium.com/@abhishekjainindore24/linker-flags-its-options-1119ff6fa7f9<br>

<h1 align="center">Loading and dynamic searching for libraries</h1>
<h3>Loader</h3>
<ul>
  <li>Loader is one of the most essentials of an OS, it loads an executable files to memory, does some preparation for the executable file, tells the OS that everything is ready and the OS passes control (lets the program do it's stuff) to the executable</li>
  <li>Maps memory of shared objects (shared libraries) to each processe's virtual memory as it's own, reallocates the virtual memory of a file</li>
  <li>Preparation of a loader means finding and doing the last bit of linking for the process</li>
</ul>


<p>Linker does static linking - meaning it links to static or dynamic libraries but NOT at run time (this would mean static)</p>
<p>Loader does dynamic linking - meaning it links to dynamic libraries but AT runtime (this would mean dynamic)</p>


<h1 align="center">Static - Dynamic libraries</h1>
<ul>
  <li>This topic is almost already hopefully clear but let's have some examples -> static libraries have .a extension, dynamic libraries have .so extension</li>
  <li>Static linking means linker will look at our code, look at what we have undefined/undeclared and COPY the actaul contents to our file FROM the static library => making the executable bigger in size, that's why loader can't link static libraries, because it would be needed to change the actual zeroes and ones of the .o file</li>
  <li>Dynamic linking happens mainly with loader and it memory maps the virtual memory of the shared object to every process that is using that very library as the process's own virtual memory</li>
</ul>

<p>the actual linking can be done by either linker hardcoding the path for the loader to look at in the ELF file's header, or looking at environment variables, or there are some directories where the loader looks defaultly - configuration file for dynamic linker or /lib and /usr/lib (/lib is for libraries that are required to run the system and /usr/lib are libraries that the user has installed and are not needed for running the system - https://unix.stackexchange.com/questions/679569/what-is-the-difference-between-lib-and-usr-lib-and-var-lib)</p>
<p>dynamic linker = dynamic loader = library loader, BUT != kernel loader (loads executables in memory), different name because the distinction between the functions its doing was necessary</p>
<p>https://stackoverflow.com/questions/9989298/what-is-the-difference-between-dynamic-linker-and-dynamic-loader</p>

<h4>theory</h4>
https://stackoverflow.com/questions/845355/do-programming-language-compilers-first-translate-to-assembly-or-directly-to-mac<br>
https://www.reddit.com/r/Compilers/comments/12lpmae/how_do_compilers_generate_an_executable/<br>
https://stackoverflow.com/questions/1785572/why-should-one-bother-with-preprocessor-directives<br>
https://www.geeksforgeeks.org/compiler-design/basic-functions-of-loader/<br>
https://unix.stackexchange.com/questions/763324/why-is-path-to-the-interpreter-hardcoded-in-elf-executables<br>
https://unix.stackexchange.com/questions/22926/where-do-executables-look-for-shared-objects-at-runtime<br>
https://stackoverflow.com/questions/56066490/at-dynamic-linking-does-the-dynamic-loader-look-at-all-object-files-for-definit<br>
https://stackoverflow.com/questions/10052464/difference-between-dynamic-loading-and-dynamic-linking#:~:text=Dynamic%20loading%20refers%20to%20mapping,or%20offsets%20%2D%20after%20compile%20time.<br>
https://developer.ibm.com/tutorials/l-dynamic-libraries/<br>
https://stackoverflow.com/questions/9989298/what-is-the-difference-between-dynamic-linker-and-dynamic-loader<br>


<h4>Practise - actual linking</h4>
https://unix.stackexchange.com/questions/452187/difference-between-the-linker-flags<br>
https://unix.stackexchange.com/questions/5915/difference-between-bin-and-usr-bin<br>
https://stackoverflow.com/questions/13795237/what-does-the-export-command-do<br>
https://www.reddit.com/r/C_Programming/comments/5pf49s/the_differences_between_using_gccg_to_compile/<br>
https://www.reddit.com/r/embedded/comments/er0skc/is_it_a_bad_look_to_use_g_compiler_when_99_of/<br>
<br><p>!Very useful! -></p>
https://stackoverflow.com/questions/16710047/usr-bin-ld-cannot-find-lnameofthelibrary<br>
https://medium.com/@abhishekjainindore24/linker-flags-its-options-1119ff6fa7f9<br>
https://tldp.org/HOWTO/Program-Library-HOWTO/shared-libraries.html<br>
https://man7.org/linux/man-pages/man8/ld.so.8.html<br>
https://en.wikipedia.org/wiki/Rpath<br>
https://unix.stackexchange.com/questions/22926/where-do-executables-look-for-shared-objects-at-runtime<br>
https://unix.stackexchange.com/questions/168340/where-is-ld-library-path-how-do-i-set-the-ld-library-path-env-variable<br>
https://askubuntu.com/questions/1128112/ld-cannot-find-shared-library<br>
https://stackoverflow.com/questions/12237282/whats-the-difference-between-so-la-and-a-library-files<br>
https://stackoverflow.com/questions/21122303/how-to-list-all-linux-environment-variables-including-ld-library-path<br>
https://stackoverflow.com/questions/4352573/linking-openssl-libraries-to-a-program<br>
https://stackoverflow.com/questions/54048981/symlink-multiple-files-to-an-existing-folder<br>
https://stackoverflow.com/questions/21361571/build-libevent-with-built-openssl-missing-libevent-openssl-so<br>
https://www.linuxfromscratch.org/blfs/view/svn/basicnet/libevent.html<br>
https://www.linuxquestions.org/questions/linux-software-2/please-difference-between-usr-include-and-usr-local-include-818767/<br>
https://stackoverflow.com/questions/9989298/what-is-the-difference-between-dynamic-linker-and-dynamic-loader<br>
