#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>

#include "runtime.h"



static void *elf_offset_ptr(const Elf64_Ehdr *base, Elf64_Off offset) {
	return (void *)((intptr_t)base + offset);
}



static void encrypt_segments(Elf64_Ehdr *elf) {
	Elf64_Ehdr ehdr;
	Elf64_Phdr *phdr_table;
	size_t phdr_table_size;
	Elf64_Phdr *phdr;
	void *addr;

	/* Close the elf header and the program headers as they will likely get
	 * encrypted during the loop. */
	ehdr = *elf;
	phdr_table_size = ehdr.e_phnum * ehdr.e_phentsize;
	phdr_table = malloc(phdr_table_size);
	if (phdr_table == NULL)
		syserr("malloc(%lu)", phdr_table_size);

	memcpy(phdr_table, elf_offset_ptr(elf, elf->e_phoff), phdr_table_size);

	for (phdr = phdr_table; phdr < &phdr_table[ehdr.e_phnum]; phdr++) {
		if (phdr->p_type != PT_LOAD)
			continue;

		addr = elf_offset_ptr(elf, phdr->p_offset);
		cipher_pages(addr, phdr->p_filesz);
	}

	free(phdr_table);
}



int main(int argc, char **argv) {
	const char *path;
	int fd;
	struct stat st;
	Elf64_Ehdr *elf;
	int err;

	if (argc != 2) {
		fprintf(stderr, "usage: %s input\n", argv[0]);
		return EXIT_FAILURE;
	}

	path = argv[1];

	init();

	fd = open(path, O_RDWR);
	if (fd == -1)
		syserr("open(\"%s\")", path);

	err = fstat(fd, &st);
	if (err == -1)
		syserr("fstat(\"%s\")", path);

	elf = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (elf == MAP_FAILED)
		syserr("mmap(\"%s\")", path);

	err = close(fd);
	if (err == -1)
		syserr("close(\"%s\")", path);

	check_elf(elf, path);
	encrypt_segments(elf);

	err = munmap(elf, st.st_size);
	if (err == -1)
		syserr("munmap(\"%s\")", path);


	return EXIT_SUCCESS;
}
