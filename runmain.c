#include <stdio.h>
#include <stdlib.h>
#include <elf.h>

#include "runtime.h"


extern Elf64_Ehdr embedded_elf;


int main(int argc, char **argv, char **envp) {
	struct process_mapping map;

	init();
	map = load_elf(&embedded_elf, 1, ":memory:");
	setup_sig_handler(&map);
	start_process(&map, argc, argv, envp);

	return EXIT_SUCCESS;
}
