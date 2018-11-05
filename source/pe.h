
#ifdef _WIN32
#include <windows.h>
#elif __linux
#include "windef.h"
#endif


namespace PELoader
{
	HMODULE Load(const void * ppe, int sztPe);

	FARPROC GetFuncAddress(HMODULE hMod, const char * szProc);

	void Release(HMODULE hMod);
}