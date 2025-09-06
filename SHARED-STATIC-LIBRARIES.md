<h1 align="center">Shared/Static libraries</h1>
<ul>
  <li>Libraries generically are just files with certain declarations, functions that could be used further for any user that gets his hands on the particular library, therefore it's just a file</li>
  <li>When we write a program, there's different stages of preparation till the file can be considered an executable file</li>
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

<p>the actual linking can be done by either linker hardcoding the path for the loader to look at in the ELF file's header, or looking at environment variables, or there are some directories where the loader looks defaultly - configuration file for dynamic linker or /lib and /usr/lib</p>
<p>dynamic linker = dynamic loader = library loader, BUT != kernel loader (loads executables in memory), different name because the distinction between the functions its doing was necessary</p>
<p>https://stackoverflow.com/questions/9989298/what-is-the-difference-between-dynamic-linker-and-dynamic-loader</p>

<h4>theory</h4>
https://stackoverflow.com/questions/845355/do-programming-language-compilers-first-translate-to-assembly-or-directly-to-mac
https://www.reddit.com/r/Compilers/comments/12lpmae/how_do_compilers_generate_an_executable/
https://stackoverflow.com/questions/1785572/why-should-one-bother-with-preprocessor-directives
https://www.geeksforgeeks.org/compiler-design/basic-functions-of-loader/
https://unix.stackexchange.com/questions/763324/why-is-path-to-the-interpreter-hardcoded-in-elf-executables
https://unix.stackexchange.com/questions/22926/where-do-executables-look-for-shared-objects-at-runtime
https://stackoverflow.com/questions/56066490/at-dynamic-linking-does-the-dynamic-loader-look-at-all-object-files-for-definit
https://stackoverflow.com/questions/10052464/difference-between-dynamic-loading-and-dynamic-linking#:~:text=Dynamic%20loading%20refers%20to%20mapping,or%20offsets%20%2D%20after%20compile%20time.
https://developer.ibm.com/tutorials/l-dynamic-libraries/
https://stackoverflow.com/questions/9989298/what-is-the-difference-between-dynamic-linker-and-dynamic-loader


<h4>Practise - actual linking</h4>
https://unix.stackexchange.com/questions/452187/difference-between-the-linker-flags
https://unix.stackexchange.com/questions/5915/difference-between-bin-and-usr-bin
https://stackoverflow.com/questions/13795237/what-does-the-export-command-do
https://www.reddit.com/r/C_Programming/comments/5pf49s/the_differences_between_using_gccg_to_compile/
https://www.reddit.com/r/embedded/comments/er0skc/is_it_a_bad_look_to_use_g_compiler_when_99_of/
<br><p>!Very useful! -></p>
https://stackoverflow.com/questions/16710047/usr-bin-ld-cannot-find-lnameofthelibrary
https://medium.com/@abhishekjainindore24/linker-flags-its-options-1119ff6fa7f9
https://tldp.org/HOWTO/Program-Library-HOWTO/shared-libraries.html
https://man7.org/linux/man-pages/man8/ld.so.8.html
https://en.wikipedia.org/wiki/Rpath
https://unix.stackexchange.com/questions/22926/where-do-executables-look-for-shared-objects-at-runtime
https://unix.stackexchange.com/questions/168340/where-is-ld-library-path-how-do-i-set-the-ld-library-path-env-variable
https://askubuntu.com/questions/1128112/ld-cannot-find-shared-library
https://stackoverflow.com/questions/12237282/whats-the-difference-between-so-la-and-a-library-files
https://stackoverflow.com/questions/21122303/how-to-list-all-linux-environment-variables-including-ld-library-path
https://stackoverflow.com/questions/4352573/linking-openssl-libraries-to-a-program
https://stackoverflow.com/questions/54048981/symlink-multiple-files-to-an-existing-folder
https://stackoverflow.com/questions/21361571/build-libevent-with-built-openssl-missing-libevent-openssl-so
https://www.linuxfromscratch.org/blfs/view/svn/basicnet/libevent.html
https://www.linuxquestions.org/questions/linux-software-2/please-difference-between-usr-include-and-usr-local-include-818767/
https://stackoverflow.com/questions/9989298/what-is-the-difference-between-dynamic-linker-and-dynamic-loader
