#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <argp.h>
#include <elf.h>
#include <unistd.h> // Include for the write function
#include <bfd.h>    // include bfd library
#include <sys/mman.h>
#include <fcntl.h>
#include <dlfcn.h>

// Challenge 1: Initialize ELF file for reading
const char *argp_program_bug_address = "<bassirou.badiane@etudiant.univ-rennes.fr>";

#define EI_NIDENT (16)

// Define the program arguments structure
struct arguments
{
    char *elfFile;
    char *binaryFile;
    char *sectionName;
    unsigned long baseAddress;
    bool modifyEntry;
};

// Define options
static struct argp_option options[] = {
    {"section", 's', "SECTION_NAME", 0, "Name of the newly created section", 0},
    {"address", 'a', "BASE_ADDRESS", 0, "Base address of the injected code", 0},
    {"modify-entry", 'm', 0, 0, "Modify the entry function", 0},
    {0}};

// Parse an option
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *arguments = state->input;

    switch (key)
    {
    case 's':
        arguments->sectionName = arg;
        break;
    case 'a':
        arguments->baseAddress = strtoul(arg, NULL, 0); // Convert string into long
        break;
    case 'm':
        arguments->modifyEntry = true;
        break;
    case ARGP_KEY_ARG:
        if (state->arg_num == 0)
            arguments->elfFile = arg;
        else if (state->arg_num == 1)
            arguments->binaryFile = arg;
        else
            argp_usage(state); // Too many arguments
        break;
    case ARGP_KEY_END:
        if (state->arg_num < 2)
            argp_usage(state); // Not enough arguments
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

// Define the argument parser
static struct argp argp = {options, parse_opt, "<elf_file> <binary_file>", "Program to analyze ELF files and inject machine code", .help_filter = NULL, .children = NULL, .argp_domain = NULL};

int main(int argc, char *argv[])
{
    struct arguments arguments = {
        .elfFile = NULL,
        .binaryFile = NULL,
        .sectionName = NULL,
        .baseAddress = 0,
        .modifyEntry = false};

    // Parse arguments
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    printf("ELF file: %s\nBinary file: %s\nSection name: %s\nBase address: 0x%lx\nModify entry: %s\n",
           arguments.elfFile, arguments.binaryFile, arguments.sectionName,
           arguments.baseAddress, arguments.modifyEntry ? "true" : "false");

    bfd *binary; // Create an bfd object

    bfd_init(); // Initialize the bfd library
    binary = bfd_openr(arguments.elfFile, NULL);
    if (binary == NULL)
    {
        fprintf(stderr, "Failed to open binary file: %s\n", bfd_errmsg(bfd_get_error()));
        exit(EXIT_FAILURE);
    }

    // Verify if the file is an elf file
    if (bfd_check_format(binary, bfd_object) == 0)
    {
        bfd_perror("bfd_check_format");
        exit(EXIT_FAILURE);
    }

    // Verify if the architecture is 64-bit
    if (bfd_get_arch_size(binary) != 64)
    {
        fprintf(stderr, "The elf file architecture is not 64-bit\n");
        exit(EXIT_FAILURE);
    }

    // Verify if the file is an executable
    if ((binary->flags & EXEC_P) == 0)
    {
        fprintf(stderr, "The elf file given is not executable\n");
        exit(EXIT_FAILURE);
    }

    // Challenge 2: Find the PT_NOTE segment header

    FILE *elfFile = fopen(arguments.elfFile, "r+b");
    if (elfFile == NULL)
    {
        fprintf(stderr, "Failed to open binary file\n");
        exit(EXIT_FAILURE);
    }
    // The fread function is used to read data from a file into a memory buffer
    // The number 1 is used as the count of elements to be read. In this case,
    // we are reading a single element of size sizeof(ExecutableHeader)
    Elf64_Ehdr e_header;
    fread(&e_header, sizeof(Elf64_Ehdr), 1, elfFile);

    size_t numProgramHeaders = e_header.e_phnum; // Number of program headers

    size_t noteSegmentIndex = 0;

    // Seek to the offset of the program headers
    // As we know, the elf elfHeader size is 64 bytes and
    // the program elfHeader section comes just after the elf elfHeader so the offset is 64
    fseek(elfFile, 64, SEEK_SET);

    // Read the size of each program elfHeader
    Elf64_Phdr p_header;
    size_t programHeaderSize = sizeof(p_header);

    for (size_t i = 0; i < numProgramHeaders; ++i)
    {

        Elf64_Phdr p_header;
        // Read each program elfHeader from the file
        fread(&p_header, programHeaderSize, 1, elfFile);

        if (p_header.p_type == PT_NOTE)
        {
            noteSegmentIndex = i;
            break;
        }
    }
    printf("Index of PT_NOTE found at %zu\n", noteSegmentIndex);
    // Challenge 3: Code Injection 

    // Open the injection code file (injected.asm) in text mode for reading
    FILE *injectionFile = fopen(arguments.binaryFile, "rb");
    if (injectionFile == NULL)
    {
        fprintf(stderr, "Failed to open injection code file\n");
        exit(EXIT_FAILURE);
    }
    // Set the cursor to the end of the file
    fseek(elfFile, 0, SEEK_END);
    // Calculate the offset where the code bytes were written
    unsigned long offset = ftell(elfFile);

    // Go to the end of file
    fseek(elfFile, offset, SEEK_SET);

    // Append the injection code to the ELF file
    size_t n;
    unsigned char buffer[8000];

    do
    {
        n = fread(buffer, 1, sizeof(buffer), injectionFile);
        if (n > 0)
        {
            ssize_t written = write(fileno(elfFile), buffer, n);
            if (written == -1)
            {
                perror("Error writing to elf file");
                exit(EXIT_FAILURE);
            }
        }
    } while (n > 0);

    printf("Injection code successfully appended to the ELF file. Offset: %ld\n", offset);

    // Ensure allignment

    while (((arguments.baseAddress - offset) % 4096) != 0)
    {

        arguments.baseAddress += ((arguments.baseAddress - offset) % 4096);
    }

    printf("Base address %ld\n", arguments.baseAddress);
    fclose(injectionFile);

    // Challenge 4: Overwriting the concerned section elfHeader

    // Set the cursor to the end of the file
    fseek(elfFile, 0, SEEK_END);
    // Offset of the end of the file
    unsigned long offsetEnd = ftell(elfFile);
    Elf64_Shdr *sectionHeader;
    Elf64_Ehdr *elfHeader;
    void *mapStart;
    struct stat st;

    // Get the size of the file
    if (fstat(fileno(elfFile), &st) < 0)
    {
        perror("Error in fstat function");
        exit(-1);
    }

    // Map the ELF file into memory
    if ((mapStart = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fileno(elfFile),
                         0)) == MAP_FAILED)
    {
        perror("Error in mmap function");
        exit(-1);
    }

    elfHeader = mapStart;
    sectionHeader = (Elf64_Shdr *)((uintptr_t)mapStart + elfHeader->e_shoff);

    // Get the index number of the section Header describing the .shstrtab section
    int shstrtab_index = elfHeader->e_shstrndx;
    int overwrittenSectionIndex = 0;
    // Loop overall section headers, inspecting each one as it goes along
    for (int i = 0; i < elfHeader->e_shnum; i++)
    {
        // Inside the loop, get the name of each iterated section elfHeader
        char *name =
            (char *)((uintptr_t)mapStart + sectionHeader[shstrtab_index].sh_offset +
                     sectionHeader[i].sh_name);

        // If the name of the current section is .note.ABI-tag, note its index and
        // overwrite the fields in the section elfHeader to turn it into a elfHeader
        // describing the injected section
        if (strcmp(name, ".note.ABI-tag") == 0)
        {
            sectionHeader[i].sh_type = SHT_PROGBITS;
            sectionHeader[i].sh_addr = arguments.baseAddress;
            sectionHeader[i].sh_offset = offset;
            sectionHeader[i].sh_size = offsetEnd - offset;
            sectionHeader[i].sh_addralign = 16;
            sectionHeader[i].sh_flags |= SHF_EXECINSTR;

            overwrittenSectionIndex = i;

            // Once the elfHeader modifications are complete, write the modified section
            // elfHeader back into the ELF binary file
            lseek(fileno(elfFile), elfHeader->e_shoff + i * sizeof(Elf64_Shdr), SEEK_SET);
            write(fileno(elfFile), &sectionHeader[i], sizeof(Elf64_Shdr));
            break;
        }
    }

    // Challenge 5: section headers calibrations

    // Get the offset of ".note.ABI-tag" into shstrtab

    int name_offset = sectionHeader[overwrittenSectionIndex].sh_name;

    // Get the offset to start of .shstrtab
    int shstrtab_offset = sectionHeader[shstrtab_index].sh_offset;

    // Compute the file offset at which to write the new section name
    int name_offset_in_file = name_offset + shstrtab_offset;

    // Check that the given name in argument has smaller length than the length of the string ".note.ABI-tag"
    if (strlen(arguments.sectionName) > strlen(".note.ABI-tag"))
    {
        fprintf(stderr, "The given section name is too long\n");
        exit(EXIT_FAILURE);
    }
    // Write the new section name to the ELF binary
    lseek(fileno(elfFile), name_offset_in_file, SEEK_SET);
    write(fileno(elfFile), arguments.sectionName, strlen(arguments.sectionName) + 1);
    printf("Section address after %ld\n", sectionHeader[overwrittenSectionIndex].sh_addr);

    // Reorder Section Headers by Section Address
    int j = overwrittenSectionIndex;
    while (j > 0 && sectionHeader[j - 1].sh_addr > sectionHeader[j].sh_addr)
    {
        Elf64_Shdr temp = sectionHeader[j];
        sectionHeader[j] = sectionHeader[j - 1];
        sectionHeader[j - 1] = temp;
        j--;
    }
    while (j < elfHeader->e_shnum - 1 &&
           sectionHeader[j + 1].sh_addr < sectionHeader[j].sh_addr)
    {
        Elf64_Shdr temp = sectionHeader[j];
        sectionHeader[j] = sectionHeader[j + 1];
        sectionHeader[j + 1] = temp;
        j++;
    }

    // Write the reordered section headers back into the ELF file
    lseek(fileno(elfFile), elfHeader->e_shoff, SEEK_SET);
    write(fileno(elfFile), sectionHeader, elfHeader->e_shnum * sizeof(Elf64_Shdr));

    // Challenge 6: Overwriting the PT_NOTE program header
    Elf64_Phdr *programHeader = (Elf64_Phdr *)((uintptr_t)mapStart + elfHeader->e_phoff);

    // Locate the PT_NOTE program header
    Elf64_Phdr *note_phdr = &programHeader[noteSegmentIndex];

    // Update the relevant fields
    note_phdr->p_type = PT_LOAD; // Denotes a loadable segment
    note_phdr->p_flags |= PF_X;  // Mark the segment as executable
    note_phdr->p_align = 0x1000; // Set alignment to a page (4096 bytes)

    // Update p_filesz and p_memsz accordingly
    note_phdr->p_filesz = offsetEnd - offset;
    note_phdr->p_memsz = offsetEnd - offset;

    // Update other fields
    note_phdr->p_offset = offset;
    note_phdr->p_vaddr = arguments.baseAddress;
    note_phdr->p_paddr = arguments.baseAddress;

    // Save the updated program header back to the binary
    lseek(fileno(elfFile), elfHeader->e_phoff + noteSegmentIndex * sizeof(Elf64_Phdr), SEEK_SET);
    write(fileno(elfFile), note_phdr, sizeof(Elf64_Phdr));

    // Challenge 7:
    // Entry Point Modification
    if (arguments.modifyEntry)
    {
        // Save the original entry point
        Elf64_Addr original_entry = elfHeader->e_entry;

        // Update the entry point to the base address of the injected code
        elfHeader->e_entry = arguments.baseAddress;

        // Write the modified ELF header back to the file
        lseek(fileno(elfFile), 0, SEEK_SET);
        write(fileno(elfFile), elfHeader, sizeof(Elf64_Ehdr));

        printf("Original entry point: 0x%lx\n", original_entry);
        printf("Modified entry point: 0x%lx\n", elfHeader->e_entry);
    }

    // Hijacking GOT Entries

     // Map the .got.plt section
    Elf64_Shdr *got_plt_section = NULL;
    for (int i = 0; i < elfHeader->e_shnum; i++)
    {
        char *name = (char *)((uintptr_t)mapStart + sectionHeader[shstrtab_index].sh_offset + sectionHeader[i].sh_name);
        if (strcmp(name, ".got.plt") == 0)
        {
            got_plt_section = &sectionHeader[i];
            break;
        }
    }

    if (got_plt_section == NULL)
    {
        fprintf(stderr, "Failed to find .got.plt section\n");
        exit(EXIT_FAILURE);
    }

    // Address of the malloc function in the Global Offset Table is 0x610188 (readelf -r --use-dynamic date | grep 'malloc')
    size_t malloc_got_address = 0x610188;
    // Fid the offset of malloc in .got.plt table
    size_t malloc_got_offset = malloc_got_address - got_plt_section->sh_addr;

    // Get the address of the malloc entry in the GOT
    Elf64_Addr *malloc_got_entry = (Elf64_Addr *)((uintptr_t)mapStart + got_plt_section->sh_offset + malloc_got_offset);

    // Overwrite the malloc GOT entry to point to the base address of the injected code
    *malloc_got_entry = arguments.baseAddress;
  
    // Unmap the memory
    munmap(mapStart, st.st_size);

    fclose(elfFile);
    bfd_close(binary);
    return 0;
}
