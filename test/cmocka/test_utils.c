#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "test_utils.h"

int compare_files(char *file1, char *file2)
{
	char ch1, ch2;
	int error = 0, pos = 0, line = 1;
	FILE *fp1;
	FILE *fp2;

	fp1 = fopen(file1, "r");
	if (!fp1)
		return -1;

	fp2 = fopen(file2, "r");
	if (!fp2) {
		fclose(fp1);
		return -1;
	}

	ch1 = getc(fp1);
	ch2 = getc(fp2);

	while (!feof(fp1) && !feof(fp2)) {
		pos++;

		if (ch1 == '\n' && ch2 == '\n') {
			line++;
			pos = 0;
		}

		if (ch1 != ch2)
			return -1;

		ch1 = getc(fp1);
		ch2 = getc(fp2);
	}

	fclose(fp1);
	fclose(fp2);
	return 0;
}
