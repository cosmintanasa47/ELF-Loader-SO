// SPDX-License-Identifier: BSD-3-Clause

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <elf.h>
#include <string.h>

void *map_elf(const char *filename)
{
	// This part helps you store the content of the ELF file inside the buffer.
	struct stat st;
	void *file;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	fstat(fd, &st);

	file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED) {
		perror("mmap");
		close(fd);
		exit(1);
	}

	return file;
}

void load_and_run(const char *filename, int argc, char **argv, char **envp)
{
	// Contents of the ELF file are in the buffer: elf_contents[x] is the x-th byte of the ELF file.
	void * elf_contents = map_elf(filename);

	/**
	 * TODO: ELF Header Validation
	 * Validate ELF magic bytes - "Not a valid ELF file" + exit code 3 if invalid.
	 * Validate ELF class is 64-bit (ELFCLASS64) - "Not a 64-bit ELF" + exit code 4 if invalid.
	 */

	char * char_contents = elf_contents; // to read byte-by-byte - no more castings for elf_contents
	for (int i = 0; i < 5; i++) {
		if (i == 4 && char_contents[i] != 2) {
			fprintf(stderr, "Not a 64-bit ELF");
			exit(4);
		} else if (i == 0 && char_contents[i] != 127) {
			fprintf(stderr, "Not a valid ELF file");
			exit(3);
		} else if (i == 1 && char_contents[i] != 'E') {
			fprintf(stderr, "Not a valid ELF file");
			exit(3);
		} else if (i == 2 && char_contents[i] != 'L') {
			fprintf(stderr, "Not a valid ELF file");
			exit(3);
		} else if (i == 3 && char_contents[i] != 'F') {
			fprintf(stderr, "Not a valid ELF file");
			exit(3);
		}
	}

    /**
     * TODO: Load PT_LOAD segments
     * For minimal syscall-only binaries.
     * For each PT_LOAD segment:
     * - Map the segments in memory. Permissions can be RWX for now.
     */
    
	Elf64_Ehdr * elf_header = elf_contents;
    Elf64_Phdr * program_header_table = (Elf64_Phdr *)(char_contents + elf_header->e_phoff);
	
	int is_pie = 0;
	if (elf_header->e_type == ET_DYN)
		is_pie = 1;
    unsigned long load_base = 0x10000;

	for (int i = 0; i < elf_header->e_phnum; i++) {
        if (program_header_table[i].p_type == PT_LOAD) {
            int page_size = 4096;
			unsigned long segment_vaddr = program_header_table[i].p_vaddr;

			if (is_pie)
				segment_vaddr += load_base;

            long aligned_vaddr = (segment_vaddr / page_size) * page_size;
            int offset_in_page = segment_vaddr - aligned_vaddr;
            long aligned_size = ((program_header_table[i].p_memsz + offset_in_page + page_size - 1) / page_size) * page_size;

            void * segment = mmap((void*)aligned_vaddr, aligned_size,
                                PROT_READ | PROT_WRITE | PROT_EXEC,
                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            
            if (segment == MAP_FAILED) {
                perror("mmap");
                exit(1);
            }

            memcpy(segment + offset_in_page, 
                   char_contents + program_header_table[i].p_offset,
                   program_header_table[i].p_filesz);

            if (program_header_table[i].p_filesz < program_header_table[i].p_memsz) {
                memset(segment + offset_in_page + program_header_table[i].p_filesz, 0,
                       program_header_table[i].p_memsz - program_header_table[i].p_filesz);
            }
        }
    }

    /**
     * TODO: Load Memory Regions with Correct Permissions
     * For each PT_LOAD segment:
     *  - Set memory permissions according to program header p_flags (PF_R, PF_W, PF_X).
     *  - Use mprotect() or map with the correct permissions directly using mmap().
     */
    for (int i = 0; i < elf_header->e_phnum; i++) {
        if (program_header_table[i].p_type == PT_LOAD) {
            int page_size = 4096;
            unsigned long segment_vaddr = program_header_table[i].p_vaddr;

			if (is_pie)
				segment_vaddr += load_base;

            long aligned_vaddr = (segment_vaddr / page_size) * page_size;
            int offset_in_page = segment_vaddr - aligned_vaddr;
            long aligned_size = ((program_header_table[i].p_memsz + offset_in_page + page_size - 1) / page_size) * page_size;

            int prot = 0;
            if (program_header_table[i].p_flags & PF_R) prot |= PROT_READ;
            if (program_header_table[i].p_flags & PF_W) prot |= PROT_WRITE;
            if (program_header_table[i].p_flags & PF_X) prot |= PROT_EXEC;

            if (mprotect((void*)aligned_vaddr, aligned_size, prot) < 0) {
                perror("mprotect");
                exit(1);
            }
        }
    }

    /**
     * TODO: Support Static Non-PIE Binaries with libc
     * Must set up a valid process stack, including:
     *  - argc, argv, envp
     *  - auxv vector (with entries like AT_PHDR, AT_PHENT, AT_PHNUM, etc.)
     * Note: Beware of the AT_RANDOM, AT_PHDR entries, the application will crash if you do not set them up properly.
     */

    // Create stack
    void * stack = mmap(NULL, 8 * 1024 * 1024, PROT_READ | PROT_WRITE, 
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (stack == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    unsigned long * sp = (unsigned long *)((char *)stack + 8 * 1024 * 1024);

    int envc = 0;
    while (envp[envc] != NULL)
        envc++;


    char * argv_addrs[argc];
    for (int i = 0; i < argc; i++) {
        int len = strlen(argv[i]) + 1;
        sp = (unsigned long *)((char *)sp - len);
        memcpy(sp, argv[i], len);
        argv_addrs[i] = (char *)sp;
    }

    char * envp_addrs[envc];
    for (int i = 0; i < envc; i++) {
        int len = strlen(envp[i]) + 1;
        sp = (unsigned long *)((char *)sp - len);
        memcpy(sp, envp[i], len);
        envp_addrs[i] = (char *)sp;
    }


    sp = (unsigned long *)((char *)sp - strlen(filename) - 1);
    memcpy(sp, filename, strlen(filename) + 1);
    char * execfn_addr = (char *)sp;


    char platform_str[] = "x86_64";
    sp = (unsigned long *)((char *)sp - strlen(platform_str) - 1);
    memcpy(sp, platform_str, strlen(platform_str) + 1);
    char * platform_addr = (char *)sp;


    char random_bytes[16];
    for (int i = 0; i < 16; i++)
        random_bytes[i] = rand() % 256;
    sp = (unsigned long *)((char *)sp - 16);
    memcpy(sp, random_bytes, 16);
    void * random_addr = sp;

    sp = (unsigned long *)((unsigned long)sp & ~0xf);

    sp--;
    *sp = 0;
    sp--;
    *sp = AT_NULL;

    sp--;
    *sp = (unsigned long)random_addr;
    sp--;
    *sp = AT_RANDOM;

    sp--;
    *sp = (unsigned long)platform_addr;
    sp--;
    *sp = AT_PLATFORM;

    sp--;
    *sp = (unsigned long)execfn_addr;
    sp--;
    *sp = AT_EXECFN;

    sp--;
    *sp = (unsigned long)elf_header->e_entry;
	unsigned long * entry_value_addr = sp;
    sp--;
    *sp = AT_ENTRY;

    sp--;
    *sp = 4096;
    sp--;
    *sp = AT_PAGESZ;

    sp--;
    *sp = (unsigned long)elf_header->e_phnum;
    sp--;
    *sp = AT_PHNUM;

    sp--;
    *sp = (unsigned long)elf_header->e_phentsize;
    sp--;
    *sp = AT_PHENT;

    sp--;
    *sp = (unsigned long)program_header_table;
	unsigned long * phdr_value_addr = sp;
    sp--;
    *sp = AT_PHDR;

    sp--;
    *sp = 0;
    for (int i = envc - 1; i > -1; i--) {
        sp--;
        *sp = (unsigned long)envp_addrs[i];
    }

    sp--;
    *sp = 0;
    for (int i = argc - 1; i > -1; i--) {
        sp--;
        *sp = (unsigned long)argv_addrs[i];
    }

    sp--;
    *sp = (unsigned long)argc;

	/**
	 * TODO: Support Static PIE Executables
	 * Map PT_LOAD segments at a random load base.
	 * Adjust virtual addresses of segments and entry point by load_base.
	 * Stack setup (argc, argv, envp, auxv) same as above.
	 */

	if (is_pie) {
		unsigned long adjusted_entry = elf_header->e_entry;
    	unsigned long adjusted_phdr = (unsigned long)program_header_table;

        adjusted_entry += load_base;
        adjusted_phdr = load_base + elf_header->e_phoff;

		*entry_value_addr = adjusted_entry;
		*phdr_value_addr = adjusted_phdr;
    }
    


	// TODO: Set the entry point and the stack pointer
	void (*entry)() = (void(*)())elf_header->e_entry;

	// Transfer control
	__asm__ __volatile__(
			"mov %0, %%rsp\n"
			"xor %%rbp, %%rbp\n"
			"jmp *%1\n"
			:
			: "r"(sp), "r"(entry)
			: "memory"
			);
}

int main(int argc, char **argv, char **envp)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <static-elf-binary>\n", argv[0]);
		exit(1);
	}

	load_and_run(argv[1], argc - 1, &argv[1], envp);
	return 0;
}