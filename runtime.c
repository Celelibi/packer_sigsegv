#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <elf.h>
#include <sys/auxv.h>

#include "runtime.h"


#ifdef __has_attribute
#	if __has_attribute(unused)
#		define _unused __attribute__((unused))
#	else
#		define _unused
#	endif
#endif

#ifndef VERBOSE
#	define VERBOSE 1
#endif

#define ARRAY_LENGTH(a) (sizeof(a) / sizeof(*(a)))

size_t PAGE_SIZE = 0;


/* Variables used in the signal handler. */
static const struct process_mapping *sig_map;
static struct sigaction oldsa;



_printf_check(2)
static int debugprintf(unsigned int level, const char *fmt, ...) {
	int ret;
	va_list ap;

	if (level > VERBOSE)
		return 0;

	va_start(ap, fmt);
	ret = vfprintf(stderr, fmt, ap);
	va_end(ap);
	return ret;
}



void syserr(const char *fmt, ...) {
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fprintf(stderr, ": ");
	perror(NULL);
	abort();
}



void usererr(const char *fmt, ...) {
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fprintf(stderr, "\n");
	abort();
}



void cipher_page(void *addr) {
	unsigned long *ptr = addr;
	size_t i;

	for (i = 0; i < PAGE_SIZE / sizeof(*ptr); i++)
		*ptr++ ^= -1;
}



void decipher_page(void *addr) {
	/* This cipher_page reverse itself. */
	cipher_page(addr);
}



static void lock_page(void *addr) {
	int err;

	err = mprotect(addr, PAGE_SIZE, PROT_READ | PROT_WRITE);
	if (err == -1)
		syserr("mprotect");

	cipher_page(addr);

	err = mprotect(addr, PAGE_SIZE, PROT_NONE);
	if (err == -1)
		syserr("mprotect");
}



static void unlock_page(void *addr, int prot) {
	int err;

	err = mprotect(addr, PAGE_SIZE, PROT_READ | PROT_WRITE);
	if (err == -1)
		syserr("mprotect");

	decipher_page(addr);

	err = mprotect(addr, PAGE_SIZE, prot);
	if (err == -1)
		syserr("mprotect");
}



void cipher_pages(void *addr, size_t size) {
	void *endaddr = (void *)((intptr_t)addr + size);

	while (addr < endaddr) {
		cipher_page(addr);
		addr = (void *)((intptr_t)addr + PAGE_SIZE);
	}
}



static void decipher_pages(void *addr, size_t size) {
	void *endaddr = (void *)((intptr_t)addr + size);

	while (addr < endaddr) {
		decipher_page(addr);
		addr = (void *)((intptr_t)addr + PAGE_SIZE);
	}
}



static void *allocate_decipher(const void *addr, size_t size) {
	const void *addralign = (const void *)((intptr_t)addr & ~(PAGE_SIZE - 1));
	size_t startoffset = (intptr_t)addr - (intptr_t)addralign;
	size_t sizealign = (size + startoffset + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	void *block;

	block = malloc(sizealign);
	if (block == NULL)
		syserr("malloc(%lu)", sizealign);

	memcpy(block, addralign, sizealign);
	decipher_pages(block, sizealign);
	memmove(block, (void *)((intptr_t)block + startoffset), size);

	/* We might have allocated almost 2 pages too much. */
	block = realloc(block, size);
	if (block == NULL)
		syserr("realloc(block, %lu)", size);

	return block;
}



static void print_maps(void) {
	FILE *fp;
	char buf[1024];
	size_t nr, nw;
	int err;

	fp = fopen("/proc/self/maps", "r");
	if (fp == NULL)
		syserr("open(\"/proc/self/maps\")");

	do {
		nr = fread(buf, sizeof(*buf), sizeof(buf), fp);
		nw = 0;
		while (nw < nr)
			nw += fwrite(buf + nw, 1, nr - nw, stdout);
	} while (nr > 0);

	err = fclose(fp);
	if (err == -1)
		syserr("fclose(\"/proc/self/maps\")");
}



void check_elf(const Elf64_Ehdr *elf, const char *filepath) {
	const unsigned char magic[] = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3};

	if (memcmp(&elf->e_ident[EI_MAG0], magic, sizeof(magic)))
		usererr("%s: ELF magic number mismatch", filepath);
	if (elf->e_ident[EI_CLASS] != ELFCLASS64)
		usererr("%s: Only 64 bits ELF are supported", filepath);
	if (elf->e_ident[EI_DATA] != ELFDATA2LSB)
		usererr("%s: Only LSB is supported", filepath);
	if (elf->e_ident[EI_VERSION] != EV_CURRENT)
		usererr("%s: Only supported ELF version is %u", filepath, EV_CURRENT);
	if (elf->e_ident[EI_OSABI] != ELFOSABI_SYSV && elf->e_ident[EI_OSABI] != ELFOSABI_GNU)
		usererr("%s: Only OSABI supported is System V", filepath);
	if (elf->e_ident[EI_ABIVERSION] != 0)
		usererr("%s: ABI version should be 0", filepath);

	if (elf->e_type != ET_DYN)
		usererr("%s: Only ELF type supported is ET_DYN", filepath);
	if (elf->e_phnum == 0)
		usererr("%s: No program header", filepath);
	if (elf->e_phentsize != sizeof(Elf64_Phdr))
		usererr("%s: Program header size not supported", filepath);
}



static void *find_load_address(const Elf64_Ehdr *elf, const Elf64_Phdr *phdr_table) {
	const Elf64_Phdr *phdr;
	Elf64_Addr minaddr = -1, maxaddr = 0;
	size_t size;
	void *ptr;

	for (phdr = phdr_table; phdr < &phdr_table[elf->e_phnum]; phdr++) {
		if (phdr->p_type != PT_LOAD)
			continue;

		if (phdr->p_vaddr < minaddr)
			minaddr = phdr->p_vaddr;
		if (phdr->p_vaddr + phdr->p_memsz > maxaddr)
			maxaddr = phdr->p_vaddr + phdr->p_memsz;
	}

	size = maxaddr - minaddr;
	ptr = mmap(NULL, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (ptr == MAP_FAILED)
		syserr("Can't find memory location to load the program");

	munmap(ptr, size);
	return ptr;
}



static struct segment_map load_segment(const void *ptr, const Elf64_Phdr *phdr,
		void *base, int preciphered) {
	void *reqaddr = NULL;
	void *addr;
	size_t bias = 0;
	void *dst, *src;
	int flags;
	struct segment_map seg;
	size_t segsz;
	int err;

	assert(phdr->p_type == PT_LOAD);

	memset(&seg, 0, sizeof(seg));

	seg.prot |= (phdr->p_flags & PF_R) ? PROT_READ : 0;
	seg.prot |= (phdr->p_flags & PF_W) ? PROT_WRITE : 0;
	seg.prot |= (phdr->p_flags & PF_X) ? PROT_EXEC : 0;

	flags = MAP_PRIVATE | MAP_ANONYMOUS;

	if (base != NULL) {
		intptr_t reqaddrraw, reqaddralign;

		flags |= MAP_FIXED_NOREPLACE;
		reqaddrraw = (intptr_t)base + phdr->p_vaddr;
		reqaddralign = reqaddrraw & ~(PAGE_SIZE - 1);
		bias = reqaddrraw - reqaddralign;
		reqaddr = (void *)reqaddralign;
	}

	addr = mmap(reqaddr, phdr->p_memsz + bias, PROT_WRITE, flags, -1, 0);
	if (addr == MAP_FAILED)
		syserr("mmap");

	if (base != NULL && addr != reqaddr)
		syserr("mmap returned an unexpected address");

	dst = (void *)((intptr_t)addr + bias);
	src = (void *)((intptr_t)ptr + phdr->p_offset);
	memcpy(dst, src, phdr->p_filesz);

	segsz = phdr->p_memsz + bias;
	segsz = (segsz + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

	if (!preciphered)
		cipher_pages(addr, segsz);

	/* Remove all access */
	err = mprotect(addr, segsz, PROT_NONE);
	if (err == -1)
		syserr("mprotect");


	seg.base = addr;
	seg.size = segsz;
	return seg;
}


struct process_mapping load_elf(const void *ptr, int preciphered, const char *filepath) {
	const Elf64_Ehdr *elf;
	const Elf64_Phdr *phdr_table;
	size_t phdr_table_size;
	const Elf64_Phdr *phdr;
	const char *interppath = NULL;
	struct process_mapping map;
	struct segment_map seg;
	size_t segno = 0;

	if (preciphered)
		elf = allocate_decipher(ptr, sizeof(*elf));
	else
		elf = ptr;

	check_elf(elf, filepath);
	memset(&map, 0, sizeof(map));
	map.prog.ehdr = *elf;

	phdr_table = (void *)((intptr_t)ptr + elf->e_phoff);
	if (preciphered) {
		phdr_table_size = elf->e_phentsize * elf->e_phnum;
		phdr_table = allocate_decipher(phdr_table, phdr_table_size);
	}

	/* Count the number of PT_LOAD program headers in order to allocate the
	 * segments array. */
	for (phdr = phdr_table; phdr < &phdr_table[elf->e_phnum]; phdr++) {
		if (phdr->p_type == PT_LOAD)
			map.prog.nsegments++;
	}

	map.prog.segments = calloc(map.prog.nsegments, sizeof(*map.prog.segments));
	if (map.prog.segments == NULL)
		syserr("calloc(%ld segments)", map.prog.nsegments);

	/* Load all the segments */
	map.prog.base = find_load_address(elf, phdr_table);
	for (phdr = phdr_table; phdr < &phdr_table[elf->e_phnum]; phdr++) {
		if (phdr->p_type != PT_LOAD)
			continue;

		seg = load_segment(ptr, phdr, map.prog.base, preciphered);
		if (map.prog.base == NULL)
			map.prog.base = seg.base;

		map.prog.segments[segno++] = seg;
	}
	map.prog.entrypoint = (void *)((intptr_t)map.prog.base + elf->e_entry);
	map.prog.phdr_table = (void *)((intptr_t)map.prog.base + elf->e_phoff);

	/* Get the interpreter path and load it if needed. */
	for (phdr = phdr_table; phdr < &phdr_table[elf->e_phnum]; phdr++) {
		if (phdr->p_type != PT_INTERP)
			continue;

		interppath = (const void *)((intptr_t)ptr + phdr->p_offset);
		if (preciphered)
			interppath = allocate_decipher(interppath, phdr->p_filesz);
	}

	if (interppath != NULL) {
		/* Ugly recursive call. */
		map.interp = load_elf_path(interppath).prog;
		map.has_interp = 1;
		map.entrypoint = map.interp.entrypoint;
		if (preciphered)
			free((void *)interppath);
	} else {
		map.entrypoint = map.prog.entrypoint;
	}

	if (preciphered) {
		free((void *)phdr_table);
		free((void *)elf);
	}

	return map;
}



struct process_mapping load_elf_path(const char *path) {
	struct process_mapping map;
	int fd;
	struct stat st;
	void *ptr;
	int err;

	fd = open(path, 0, O_RDONLY);
	if (fd == -1)
		syserr("open(\"%s\")", path);

	err = fstat(fd, &st);
	if (err == -1)
		syserr("fstat(\"%s\")", path);

	ptr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (ptr == MAP_FAILED)
		syserr("mmap(\"%s\")", path);

	err = close(fd);
	if (err == -1)
		syserr("close(\"%s\")", path);

	map = load_elf(ptr, 0, path);

	err = munmap(ptr, st.st_size);
	if (err == -1)
		syserr("munmap(\"%s\")", path);

	return map;
}



static void reset_sig_handler(void) {
	struct sigaction sa;
	int err;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_DFL;

	err = sigaction(SIGSEGV, &sa, NULL);
	if (err == -1)
		syserr("sigaction(SIGSEGV)");
}



static struct segment_map *segment_lookup(const struct process_mapping *map, const void *addr) {
	struct segment_map *seg;
	size_t i;

	for (i = 0; i < map->prog.nsegments; i++) {
		seg = &map->prog.segments[i];
		if (addr >= seg->base && addr < (void *)((intptr_t)seg->base + seg->size))
			return seg;
	}

	for (i = 0; i < map->interp.nsegments; i++) {
		seg = &map->interp.segments[i];
		if (addr >= seg->base && addr < (void *)((intptr_t)seg->base + seg->size))
			return seg;
	}

	return NULL;
}



static void dump_map(const struct process_mapping *map) {
	size_t i;

	debugprintf(1, "Prog base: 0x%08lx\n", (intptr_t)map->prog.base);
	for (i = 0; i < map->prog.nsegments; i++) {
		const struct segment_map *seg = &map->prog.segments[i];
		const void *start = seg->base;
		const void *end = (void *)((intptr_t)seg->base + seg->size);

		debugprintf(1, "\tSegment %lu start: 0x%08lx, end: 0x%08lx, prot: %d\n", i, (intptr_t)start, (intptr_t)end, seg->prot);
	}
	debugprintf(1, "\n");

	debugprintf(1, "Interp base: 0x%08lx\n", (intptr_t)map->interp.base);
	for (i = 0; i < map->interp.nsegments; i++) {
		const struct segment_map *seg = &map->interp.segments[i];
		const void *start = seg->base;
		const void *end = (void *)((intptr_t)seg->base + seg->size);

		debugprintf(1, "\tSegment %lu start: 0x%08lx, end: 0x%08lx, prot: %d\n", i, (intptr_t)start, (intptr_t)end, seg->prot);
	}
	debugprintf(1, "\n");
}



static void forward_sigsegv(siginfo_t *si, void *uctxt) {
	debugprintf(2, "Forwarding SIGSEGV\n");
	if (oldsa.sa_flags & SA_SIGINFO && oldsa.sa_sigaction != NULL) {
		oldsa.sa_sigaction(SIGSEGV, si, uctxt);
		return;
	}
	if (oldsa.sa_handler != NULL) {
		oldsa.sa_handler(SIGSEGV);
		return;
	}

	debugprintf(1, "Oops, not my segment\n");
	debugprintf(1, "Error at: 0x%08lx\n", (intptr_t)si->si_addr);
	dump_map(sig_map);
	print_maps();

	reset_sig_handler();
	/* If this signal come from the user, send it again. */
	if (si->si_code <= 0)
		kill(getpid(), SIGSEGV);

	/* If it comes from the kernel, returning from it should trigger
	 * it again. */
	abort();
	return;
}



static void sigsegv(_unused int signal, siginfo_t *si, _unused void *uctxt) {
	struct segment_map *segfault;
	void *addr;
	static void **pp;

	debugprintf(2, "Caught a SIGSEGV code: %d, address: 0x%08lx\n", si->si_code, (intptr_t)si->si_addr);

	/* If this SIGSEGV wasn't expected. Try to die "naturally" from it. */
	if (si->si_code != SEGV_ACCERR) {
		forward_sigsegv(si, uctxt);
		return;
	}

	/* Lookup the segment where the fault happened. */
	segfault = segment_lookup(sig_map, si->si_addr);
	if (segfault == NULL) {
		forward_sigsegv(si, uctxt);
		return;
	}

	pp = segfault->plain_pages;
	if (pp[0] != NULL) {
		debugprintf(2, "Removing access to page 0x%08lx\n", (intptr_t)pp[0]);
		lock_page(pp[0]);
	}

	addr = (void *)((intptr_t)si->si_addr & ~(PAGE_SIZE - 1));

	debugprintf(2, "Enabling access %d to page 0x%08lx for fault at 0x%08lx\n", segfault->prot, (intptr_t)addr, (intptr_t)si->si_addr);
	unlock_page(addr, segfault->prot);

	memmove(pp, pp + 1, sizeof(segfault->plain_pages) - sizeof(*pp));
	segfault->plain_pages[ARRAY_LENGTH(segfault->plain_pages) - 1] = addr;
}



void setup_sig_handler(const struct process_mapping *map) {
	struct sigaction sa;
	int err;

	debugprintf(1, "Setting up SIGSEGV handler\n");
	memset(&sa, 0, sizeof(sa));

	sig_map = map;
	sa.sa_sigaction = sigsegv;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_NODEFER | SA_SIGINFO;

	err = sigaction(SIGSEGV, &sa, &oldsa);
	if (err == -1)
		syserr("sigaction(SIGSEGV)");
	debugprintf(1, "SIGSEGV handler all set up\n");
}



void start_process(const struct process_mapping *map, int argc, char **argv, char **envp) {
	Elf64_Addr *sp;
	int envc = 0;
	size_t stacksize;
	int auxc = 0;
	Elf64_auxv_t aux, *auxp;
	int i;

	while (envp[envc] != NULL)
		envc++;

	debugprintf(1, "envc = %d\n", envc);

	/* Count the auxv entries assuming all the auxv types are less than 256. */
	for (i = 0; i < 256; i++) {
		errno = 0;
		getauxval(i);
		if (errno == 0)
			auxc++;
	}
	debugprintf(1, "auxc = %d\n", auxc);

	/* alloca will always allocate the array on the top of the stack. */
	stacksize = sizeof(*sp) * (1 + (argc + 1) + (envc + 1));
	stacksize += (auxc + 1) * sizeof(Elf64_auxv_t);
	sp = alloca(stacksize);

	*sp++ = argc;
	while (*argv)
		*sp++ = (Elf64_Addr)*argv++;
	*sp++ = 0;
	while (*envp)
		*sp++ = (Elf64_Addr)*envp++;
	*sp++ = 0;

	auxp = (Elf64_auxv_t *)sp;
	for (aux.a_type = 0; aux.a_type < 256; aux.a_type++) {
		errno = 0;
		aux.a_un.a_val = getauxval(aux.a_type);
		if (errno != 0)
			continue;

		switch (aux.a_type) {
		case AT_BASE:
			aux.a_un.a_val = (intptr_t)map->interp.base;
			break;
		case AT_ENTRY:
			aux.a_un.a_val = (intptr_t)map->prog.entrypoint;
			break;
		case AT_PHDR:
			aux.a_un.a_val = (intptr_t)map->prog.phdr_table;
			break;
		case AT_PHENT:
			aux.a_un.a_val = map->prog.ehdr.e_phentsize;
			break;
		case AT_PHNUM:
			aux.a_un.a_val = map->prog.ehdr.e_phnum;
			break;
		}

		*auxp++ = aux;
	}
	aux.a_type = 0;
	aux.a_un.a_val = 0;
	*auxp++ = aux;

	sp = (Elf64_Addr *)auxp;

	if (VERBOSE > 0) {
		print_maps();
		dump_map(sig_map);
	}
	/*goto *ep;*/
	__asm__ ("jmp *%0" : : "m"(map->entrypoint));
}



void init(void) {
	PAGE_SIZE = sysconf(_SC_PAGE_SIZE);
}
