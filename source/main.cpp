#include <stdio.h>
#include <stdlib.h>
#include "pe.h"
#include "log.h"

void PrintfHelp(const char *appName)
{
	printf("Using: %s <exe/dll file>\n", appName);
}

int main(int argc, char *argv[])
{
	LogInitConsole(LogLevel_Max);

	if (argc < 2)
	{
		PrintfHelp(argv[0]);
	}
	else
	{
		FILE * fPE = fopen(argv[1], "rb");
		if (fPE == nullptr)
		{
			printf("Can't open file [%s]\n", argv[1]);
		}
		else
		{
			fseek(fPE, 0, SEEK_END);
			unsigned int fileSize = ftell(fPE);
			fseek(fPE, 0, SEEK_SET);

			void * pe = malloc(fileSize);
			if (pe == nullptr)
			{
				printf("Out of memory, alloc(%d)\n", fileSize);
			}
			else
			{
				fread(pe, fileSize, 1, fPE);
				PELoader::Release(PELoader::Load(pe, fileSize));

				free(pe);
			}

			fclose(fPE);
		}
	}

	return 0;
}