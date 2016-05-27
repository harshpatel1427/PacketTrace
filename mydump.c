#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "arguments.h"

extern sniffPackets(char *, char *);
extern dumpPcapFile(char *, char *);
char *pattern;

int main(int argc, char *argv[]) {
	int rc,option;
	unsigned int iflag = 0, rflag = 0, sflag = 0, eflag = 0;
	char usage[] = "Usage: mydump [-h] [-i interface] [-r filename] [-s string] [expression] \n";
	char optstring[] = "hi:r:s:e";
	
	arg_t arguments;
	char *interface, *fileName, *expression;

	// Intializing arguments to their default value
	arguments.interface = (char *) malloc(sizeof (char *));	
	strcpy(arguments.interface, " ");
	arguments.fileName = (char *) malloc(sizeof (char *));	
	strcpy(arguments.fileName, "");
	arguments.string = (char *) malloc(sizeof (char *));	
	strcpy(arguments.string, "");
	arguments.expression = (char *) malloc(sizeof (char *));	
	strcpy(arguments.expression, "");


	while((option = getopt(argc, argv, optstring)) != (-1)) {
		switch(option) {
			
			case 'i':
				iflag++;
				arguments.interface = optarg;
				break;
			
			case 'r':
				rflag++;
				arguments.fileName = optarg;
				break;
			
			case 's':
				sflag++;
				arguments.string= optarg;
				break;

			case 'h':
				printf("%s", usage);
				break;
	
			case '?':		
				printf("Invalid Character %c found\n For help use -h\n", optopt);
				exit(-1);
				break;
		}
	}
	if (iflag > 1 || rflag > 1 || sflag > 1 || (iflag == 1 && rflag == 1)) {
		printf("Invalid Option in argument. Use -h for more help of command usage.\n");
		exit(-1);
	}

	while (optind < argc) {
		strcat(strcat(arguments.expression, " "), argv[optind++]);
	}
	pattern = strdup(arguments.string);
	if (rflag == 1) {
		/* Read from file */	
		dumpPcapFile(arguments.fileName, arguments.expression);
		goto ret;		
	}
	
	/* Capturing packets through interface */
	sniffPackets(arguments.interface, arguments.expression);
ret:
	return 0;
}

