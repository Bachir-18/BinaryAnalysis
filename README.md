# BinaryAnalysis

The project outlined in the document focuses on advanced binary modification techniques, particularly for ELF (Executable and Linkable Format) binaries. The goal is to teach how to inject new code into an existing binary and modify it in various ways, leveraging key concepts in software security.  

Key Objectives:

1. Binary Code Injection: The project involves injecting new code into an ELF binary and updating the relevant headers to ensure the new section is loaded and executed.
2. Modification of ELF Headers: We must modify both section and program headers, specifically the PT_NOTE segment, to accommodate the new code.
3. Execution of Injected Code: The injected code is expected to be executed, with options to modify the ELF's entry point or hijack the Global Offset Table (GOT) for repeated execution.


To execute the program

make -C src  

./executable date injected.bin -a 0x500000 -s new.section [-m]
