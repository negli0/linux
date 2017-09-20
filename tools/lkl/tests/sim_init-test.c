#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "test.h"

#include <lkl.h>
#include <lkl_host.h>

/* 
 * just call sim_init() and return
 * 
 */
int main(int argc, char **argv) 
{
	char boot_cmdline[256] = {'\0'};
	int kernel;
	int ret = 0;

	/* call lkl_start_kernel() in sim_init() */
	//ret = sim_init(&lkl_host_ops, boot_cmdline);
	sim_init(&lkl_host_ops, boot_cmdline, &kernel);
	//lkl_start_kernel(&lkl_host_ops, "");
	if (ret < 0) {
		fprintf(stderr, "cannot start kernel: %d\n", ret);
		exit(ret);
	}

	return 0;
}
