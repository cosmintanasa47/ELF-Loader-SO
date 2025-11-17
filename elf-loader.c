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
	void *elf_contents = map_elf(filename);

	/**
	 * TODO: ELF Header Validation
	 * Validate ELF magic bytes - "Not a valid ELF file" + exit code 3 if invalid.
	 * Validate ELF class is 64-bit (ELFCLASS64) - "Not a 64-bit ELF" + exit code 4 if invalid.
	 */

	char* char_contents = elf_contents; // to read byte-by-byte - no more castings for elf_contents
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

	Elf64_Ehdr* elf_header = elf_contents;
	Elf64_Phdr* program_header_table = (Elf64_Phdr*)(char_contents + elf_header->e_phoff);
	for (int i = 0; i < elf_header->e_phnum; i++) {
		int page_size = 4096;
    	long aligned_vaddr = (program_header_table[i].p_vaddr / page_size) * page_size;
		int offset_in_page = program_header_table[i].p_vaddr % page_size;
		int aligned_size = ((program_header_table[i].p_memsz + offset_in_page + page_size - 1) / page_size) * page_size;

		if (program_header_table[i].p_type == PT_LOAD) {
			void* to_be_loaded = mmap((void*)aligned_vaddr,
			aligned_size, PROT_WRITE | PROT_EXEC | PROT_READ,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
			
			if (to_be_loaded == MAP_FAILED){
				perror("mmap");
				exit(1);
			}

			void* where_written = memcpy(to_be_loaded + offset_in_page, char_contents + program_header_table[i].p_offset,
										program_header_table[i].p_filesz);

			if (program_header_table[i].p_filesz < program_header_table[i].p_memsz) {
				memset((char*)to_be_loaded + program_header_table[i].p_filesz, 0,
						program_header_table[i].p_memsz - program_header_table[i].p_filesz);
			}
		}
	}

	/**
	 * TODO: Load Memory Regions with Correct Permissions
	 * For each PT_LOAD segment:
	 *	- Set memory permissions according to program header p_flags (PF_R, PF_W, PF_X).
	 *	- Use mprotect() or map with the correct permissions directly using mmap().
	 */

	for (int i = 0; i < elf_header->e_phnum; i++) {
		int page_size = 4096;
    	long aligned_vaddr = (program_header_table[i].p_vaddr / page_size) * page_size;
		int offset_in_page = program_header_table[i].p_vaddr % page_size;
		int aligned_size = ((program_header_table[i].p_memsz + offset_in_page + page_size - 1) / page_size) * page_size;

		if (program_header_table[i].p_type == PT_LOAD) {
			int result_mprotect = mprotect((void*)aligned_vaddr, aligned_size, program_header_table[i].p_flags);
			if (result_mprotect < 0) {
				perror("mprotect");
				exit(1);
			}
		}
	}


	/**
	 * TODO: Support Static Non-PIE Binaries with libc
	 * Must set up a valid process stack, including:
	 *	- argc, argv, envp
	 *	- auxv vector (with entries like AT_PHDR, AT_PHENT, AT_PHNUM, etc.)
	 * Note: Beware of the AT_RANDOM, AT_PHDR entries, the application will crash if you do not set them up properly.
	 */

	void* stack = mmap(NULL, 8 * 1024 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (stack == MAP_FAILED) {
    	perror("mmap");
    	exit(1);
	}
	long* sp = (long*)((char*)stack + 8 * 1024 * 1024);
	
	int envc = 0;
	while (envp[envc] != NULL)
		envc++;


//================================================== STRINGS - NECESARY ???

	//*sp = 0; // NULL terminator
	
	// 4. auxv array
	//Elf64_Ehdr* elf_header = elf_contents;
	//Elf64_Phdr* program_header_table = (Elf64_Phdr*)(char_contents + elf_header->e_phoff);

	//uint64_t phdr_addr = (uint64_t)program_header_table;
	//uint64_t entry_addr = elf_header->e_entry;
	



//=================================================  AUXV
	*sp = 0;
	sp--;
	*sp = (long)AT_NULL;
	sp--;

	char platform_addr[] = "x86_64";
	*sp = (long)(&platform_addr);
	sp--;
	*sp = (long)AT_PLATFORM;
	sp--;


	char* file = strdup(filename);
	*sp = (long)file;
	sp--;
	*sp = (long)AT_EXECFN;
	sp--;


	char random_content[16];
	srand(7);
	for (int i = 0; i < 16; i++) {
		random_content[i] = rand();
	}
	*sp = (long)&random_content;
	sp--;
	*sp = (long)AT_RANDOM;
	sp--;

	*sp = (long)program_header_table;
	sp--;
	*sp = (long)AT_PHDR;
	sp--;
	
	*sp = (long)elf_header->e_phentsize;
	sp--;
	*sp = (long)AT_PHENT;
	sp--;
	
	*sp = (long)elf_header->e_phnum;
	sp--;
	*sp = (long)AT_PHNUM;
	sp--;
	
	*sp = 4096;
	sp--;
	*sp = (long)AT_PAGESZ;
	sp--;
	
	*sp = (long)elf_header->e_entry;
	sp--;
	*sp = (long)AT_ENTRY;
	sp--;
	
//================================================== ENVP

	*sp = 0;
	sp--;

	for (int i = envc - 1; i > -1; i--) {
		*sp = (long)(envp[i]);
		sp--;
	}

//=================================================== ARGS

	*sp = 0;
	sp--;

	for (int i = envc - 1; i > -1; i--) {
		*sp = (long)(argv[i]);
		sp--;
	}

//=================================================== ARGC

	*sp = (long)argc;


	/**
	 * TODO: Support Static PIE Executables
	 * Map PT_LOAD segments at a random load base.
	 * Adjust virtual addresses of segments and entry point by load_base.
	 * Stack setup (argc, argv, envp, auxv) same as above.
	 */

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
