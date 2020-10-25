#ifndef RUNTIME_H_
#define RUNTIME_H_

#include <stddef.h>
#include <stdint.h>
#include <elf.h>



#ifdef __has_attribute
#	if __has_attribute(format)
#		define _printf_check(i) __attribute__((format(printf, i, i+1)))
#	else
#		define _printf_check
#	endif
#endif



struct segment_map {
	void *base;
	size_t size;
	uint32_t prot;

	/*
	 * The page indexes that are currently accessible as intended. The array
	 * size should be at least 2 to handle unaligned accesses.
	 * There should probably be a copy of this field for every thread.
	 */
	void *plain_pages[2];
};



struct elf_mapping {
	Elf64_Ehdr ehdr;
	Elf64_Phdr *phdr_table;
	void *base;
	void *entrypoint;
	size_t nsegments;
	struct segment_map *segments;
};



struct process_mapping {
	struct elf_mapping prog;
	struct elf_mapping interp;
	char has_interp;
	void *entrypoint;
};


_printf_check(1)
void syserr(const char *fmt, ...);

_printf_check(1)
void usererr(const char *fmt, ...);

void init(void);
struct process_mapping load_elf_path(const char *path);
void setup_sig_handler(const struct process_mapping *map);
void start_process(const struct process_mapping *map, int argc, char **argv, char **envp);

#endif
