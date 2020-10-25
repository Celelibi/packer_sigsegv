#include <stdio.h>
#include <stdlib.h>

#include "runtime.h"



int main(int argc, char **argv, char **envp) {
	struct process_mapping map;

	if (argc < 2) {
		fprintf(stderr, "usage: %s ELFpath\n", argv[0]);
		return EXIT_FAILURE;
	}

	init();
	map = load_elf_path(argv[1]);
	setup_sig_handler(&map);
	start_process(&map, argc - 1, argv + 1, envp);

	return EXIT_SUCCESS;
}
