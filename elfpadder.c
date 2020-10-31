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



static Elf64_Off round_down_page(Elf64_Off off) {
	return off & ~(PAGE_SIZE - 1);
}



static Elf64_Off round_up_page(Elf64_Off off) {
	return round_down_page(off + PAGE_SIZE - 1);
}



static Elf64_Off segment_vaddr_to_offset(const Elf64_Phdr *phdr, Elf64_Addr addr) {
	return addr - phdr->p_vaddr + phdr->p_offset;
}



static Elf64_Off segment_end_voffset(const Elf64_Phdr *phdr) {
	return segment_vaddr_to_offset(phdr, round_up_page(phdr->p_vaddr + phdr->p_filesz));
}



size_t pad_location_size(const Elf64_Ehdr *elf, Elf64_Off *offset) {
	Elf64_Phdr *phdr_table = elf_offset_ptr(elf, elf->e_phoff);
	Elf64_Phdr *phdr, *pphdr;
	Elf64_Off psegend, segbegin;

	pphdr = NULL;
	for (phdr = phdr_table; phdr < &phdr_table[elf->e_phnum]; phdr++) {
		if (phdr->p_type != PT_LOAD)
			continue;

		if (pphdr == NULL) {
			pphdr = phdr;
			continue;
		}

		/* Check that the segments are sorted. */
		if (pphdr->p_vaddr >= phdr->p_vaddr)
			usererr("PT_LOAD segments not sorted by virtual addresses");
		if (pphdr->p_offset >= phdr->p_offset)
			usererr("PT_LOAD segments not sorted by file offset");

		/* Check there is no overlap in memory (shouldn't happen). */
		if (pphdr->p_vaddr + pphdr->p_memsz > phdr->p_vaddr)
			usererr("PT_LOAD segments overlap in memory");
		if (pphdr->p_offset + pphdr->p_filesz > phdr->p_offset)
			usererr("PT_LOAD segments overlap in file");

		psegend = segment_end_voffset(pphdr);
		segbegin = phdr->p_offset;

		if (psegend > segbegin) {
			if (offset != NULL)
				*offset = segbegin;
			/* Round up to a page to avoid messing up any alignment. */
			return round_up_page(psegend - segbegin);
		}

		pphdr = phdr;
	}

	if (offset != NULL)
		*offset = 0;
	return 0;
}



static void fixup_ehdr(Elf64_Ehdr *elf, Elf64_Off offset, size_t padsize) {
	if (elf->e_phoff > offset)
		elf->e_phoff += padsize;
	if (elf->e_shoff > offset)
		elf->e_shoff += padsize;
	if (elf->e_ehsize > offset)
		elf->e_ehsize += padsize;
}



static void fixup_phdr(Elf64_Ehdr *elf, Elf64_Off offset, size_t padsize) {
	Elf64_Phdr *phdr_table = elf_offset_ptr(elf, elf->e_phoff);
	Elf64_Phdr *phdr;

	for (phdr = phdr_table; phdr < &phdr_table[elf->e_phnum]; phdr++) {
		if (phdr->p_offset >= offset)
			phdr->p_offset += padsize;
		else if (phdr->p_offset + phdr->p_filesz > offset)
			phdr->p_filesz += padsize;
	}
}



/* Fixing section headers is optional. It just helps with debugging. */
static void fixup_shdr(Elf64_Ehdr *elf, Elf64_Off offset, size_t padsize) {
	Elf64_Shdr *shdr_table = elf_offset_ptr(elf, elf->e_shoff);
	Elf64_Shdr *shdr;

	for (shdr = shdr_table; shdr < &shdr_table[elf->e_shnum]; shdr++) {
		if (shdr->sh_offset >= offset)
			shdr->sh_offset += padsize;
		else if (shdr->sh_offset + shdr->sh_size > offset)
			shdr->sh_size += padsize;
	}
}



static void pad_elf_at(Elf64_Ehdr *elf, size_t oldsize, Elf64_Off offset, size_t padsize) {
	void *src = elf_offset_ptr(elf, offset);
	void *dst = elf_offset_ptr(elf, offset + padsize);

	memmove(dst, src, oldsize - offset);
	memset(src, 0, padsize);

	fixup_ehdr(elf, offset, padsize);
	fixup_phdr(elf, offset, padsize);
	fixup_shdr(elf, offset, padsize);
}



static int pad_elf_once(int fd, const char *path) {
	struct stat st;
	off_t oldsize, newsize;
	Elf64_Ehdr *elf;
	size_t padsize;
	Elf64_Off padoff;
	int err;
	off_t off;
	ssize_t nw;


	err = fstat(fd, &st);
	if (err == -1)
		syserr("fstat(\"%s\")", path);

	oldsize = st.st_size;

	elf = mmap(NULL, oldsize, PROT_READ, MAP_PRIVATE, fd, 0);
	if (elf == MAP_FAILED)
		syserr("mmap(\"%s\")", path);

	check_elf(elf, path);
	padsize = pad_location_size(elf, &padoff);

	err = munmap(elf, oldsize);
	if (err == -1)
		syserr("munmap(\"%s\")", path);

	if (padsize == 0)
		return 0;

	/* Seek and write a byte to increase the file size. */
	newsize = oldsize + padsize;
	off = lseek(fd, padsize - 1, SEEK_END);
	if (off == (off_t)-1)
		syserr("lseek(\"%s\", %ld, SEEK_END)", path, padsize - 1);

	nw = write(fd, "\0", sizeof(char));
	if (nw == -1)
		syserr("write(\"%s\", \"\\0\", %ld)", path, sizeof(char));

	elf = mmap(NULL, newsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (elf == MAP_FAILED)
		syserr("mmap(\"%s\")", path);

	pad_elf_at(elf, oldsize, padoff, padsize);

	err = munmap(elf, newsize);
	if (err == -1)
		syserr("munmap(\"%s\")", path);

	return padsize;
}



static void pad_elf(const char *path) {
	int fd;
	int padded;
	int err;

	/* Open the file only once to avoid race conditions. */
	fd = open(path, O_RDWR);
	if (fd == -1)
		syserr("open(\"%s\")", path);

	/* Re-pad while necessary. */
	do {
		padded = pad_elf_once(fd, path);
	} while (padded);

	err = close(fd);
	if (err == -1)
		syserr("close(\"%s\")", path);
}



int main(int argc, char **argv) {
	const char *elfpath;

	if (argc != 2) {
		fprintf(stderr, "usage: %s elfpath\n", argv[0]);
		return EXIT_FAILURE;
	}

	elfpath = argv[1];
	init();
	pad_elf(elfpath);


	return EXIT_SUCCESS;
}
