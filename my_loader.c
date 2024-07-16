#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <elf.h>
#include <string.h>

int fd;

int foreach_phdr(void *map_start, void (*func)(Elf32_Phdr *, int), int arg);
void print_phdr_details(Elf32_Phdr *phdr, int index);
void load_phdr_segment(Elf32_Phdr *phdr, int index);
void load_phdr(Elf32_Phdr *phdr , int fd);
int startup(int argc, char **argv, void (*start)());


// Function to iterate over program headers and apply a callback function - For Task 0
int foreach_phdr(void *map_start, void (*func)(Elf32_Phdr *, int), int arg) {
    Elf32_Ehdr *header = (Elf32_Ehdr *)map_start;
    Elf32_Phdr *phdr = (Elf32_Phdr *)(map_start + header->e_phoff);
    for (int i = 0; i < header->e_phnum; i++) {
        func(&phdr[i], i);
    }
    return 0;
}

// Callback function to print detailed information about each program header
void print_phdr_details(Elf32_Phdr *phdr, int index) {
    const char *type;
    switch (phdr->p_type) {
        case PT_NULL: type = "NULL"; break; //unused header
        case PT_LOAD: type = "LOAD"; break; // a segment that should be loaded into memory - information about the file
        case PT_DYNAMIC: type = "DYNAMIC"; break; //dynamic linking information
        case PT_INTERP: type = "INTERP"; break; //  path to the interpreter (dynamic linker) 
        case PT_NOTE: type = "NOTE"; break; // auxiliary information
        case PT_SHLIB: type = "SHLIB"; break; //unspecified semantics
        case PT_PHDR: type = "PHDR"; break; //program header table itself
        case PT_TLS: type = "TLS"; break; //hread-local storage (TLS) templates
        case PT_GNU_EH_FRAME: type = "GNU_EH_FRAME"; break; //exception handling information
        case PT_GNU_STACK: type = "GNU_STACK"; break; //stack permissions
        case PT_GNU_RELRO: type = "GNU_RELRO"; break; //should be made read-only after relocation
        case PT_SUNWBSS: type = "SUNWBSS"; break; // uninitialized data
        case PT_SUNWSTACK: type = "SUNWSTACK"; break; //stack permissions
        default: type = "UNKNOWN"; break;
    }

    // Determine the flags
    char flags[4] = "   ";
    if (phdr->p_flags & PF_R) flags[0] = 'R';
    if (phdr->p_flags & PF_W) flags[1] = 'W';
    if (phdr->p_flags & PF_X) flags[2] = 'E';

    // Translate ELF flags to mmap protection flags
    int prot = 0;
    if (phdr->p_flags & PF_R) prot |= PROT_READ;
    if (phdr->p_flags & PF_W) prot |= PROT_WRITE;
    if (phdr->p_flags & PF_X) prot |= PROT_EXEC;

    // Typically, we use MAP_PRIVATE for mapping ELF segments
    int map_flags = MAP_PRIVATE;
    
    printf("%-15s 0x%06x 0x%08x 0x%08x 0x%05x 0x%05x %s 0x%04x 0x%02x       0x%02x\n",
           type,
           phdr->p_offset,
           phdr->p_vaddr,
           phdr->p_paddr,
           phdr->p_filesz,
           phdr->p_memsz,
           flags,
           phdr->p_align,
           prot,
           map_flags);

}

void load_phdr_segment(Elf32_Phdr *phdr, int index) {
    if (phdr->p_type == PT_LOAD) {
        int prot = 0;
        if (phdr->p_flags & PF_R) prot |= PROT_READ;
        if (phdr->p_flags & PF_W) prot |= PROT_WRITE;
        if (phdr->p_flags & PF_X) prot |= PROT_EXEC;

        Elf32_Addr vaddr = phdr->p_vaddr&0xfffff000;
        Elf32_Off offset = phdr->p_offset&0xfffff000;
        Elf32_Addr padding = phdr->p_vaddr&0xfff;
        void * addr = mmap((void *) vaddr, phdr->p_memsz+padding, prot, MAP_PRIVATE | MAP_FIXED, fd, offset);   

        if (addr == MAP_FAILED) {
            perror("mmap");
            exit(1);
        }
    }
}


void load_phdr(Elf32_Phdr *phdr, int fd) {
    // Validate arguments
    if (!phdr) {
        fprintf(stderr, "Invalid program header pointer\n");
        exit(1);
    }

    // Iterate through each program header
    for (int i = 0; phdr[i].p_type != PT_NULL; i++) {
        // Print detailed information about the program header
        print_phdr_details(&phdr[i], i);

        // Load PT_LOAD segment into memory
        load_phdr_segment(&phdr[i], i);
        
    }
}





int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ELF file>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        perror("open");
        return 1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        perror("fstat");
        close(fd);
        return 1;
    }

    void *map_start = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map_start == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

     // Cast map_start to Elf32_Ehdr* to access ELF header
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)map_start;

    // Calculate the start of program headers
    Elf32_Phdr *phdr = (Elf32_Phdr *)((char *)map_start + ehdr->e_phoff);

    // Print the table header with additional columns
    printf("%-15s %-10s %-10s %-10s %-10s %-10s %-4s %-5s %-9s %-9s\n",
           "Type",
           "Offset",
           "VirtAddr",
           "PhysAddr",
           "FileSiz",
           "MemSiz",
           "Flg",
           "Align",
           "ProtFlags",
           "MapFlags");

    load_phdr(phdr,fd);

    startup(argc-1, argv+1, (void (*)(void)) ehdr->e_entry);

    if (munmap(map_start, st.st_size) != 0) {
        perror("munmap");
        return 1;
    }
    close(fd);

    return 0;
}


