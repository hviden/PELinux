
#ifdef _WIN64
#define POINTER_TYPE unsigned long long
#else
#define POINTER_TYPE unsigned long
#endif

#ifdef _WIN32
#include <windows.h>
#elif __linux
#include <unistd.h>
#include <dlfcn.h>
#endif

#include "pe.h"
#include "log.h"
#include "common.h"
#include <string.h>

namespace PELoader
{
	HMODULE LoadLib(const char *libName)
	{
#ifdef __linux
		if (strcasecmp(libName, "msvcrt.dll") == 0)
		{
			return dlopen("libc.so.6", RTLD_NOW);
		}
#elif _WIN32
		return LoadLibraryA(libName);
#endif
		return nullptr;
	}

	// re-name it
	FARPROC GetLibFunAddress(HMODULE hModule, LPCSTR lpProcName)
	{
		// not support get ordinal yet
#ifdef __linux
		return (FARPROC)dlsym(hModule, lpProcName);
#elif _WIN32
		return GetProcAddress(hModule, lpProcName);
#endif
	}

	bool DoBaseReloc(unsigned char *codeBase, size_t codeSize, size_t delta, IMAGE_BASE_RELOCATION *pBaseReloc, int remainSize)
	{
		bool ret = true;
		while (remainSize > 0 && ret)
		{
			WORD *arrRel = (WORD *)&pBaseReloc[1];
			int nRel = (pBaseReloc[0].SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			char *dest = (char*)codeBase + pBaseReloc[0].VirtualAddress;

			if (dest < (char*)codeBase || (char*)codeBase + codeSize < dest)
			{
				ret = false;
			}
			else for (int i = 0; i < nRel; ++i)
			{
				DWORD *patchAddrHL;
#ifdef _WIN64
				ULONGLONG *patchAddr64;
#endif
				int offset = arrRel[i] & 0xfff;
				switch (arrRel[i] >> 12)
				{
				case IMAGE_REL_BASED_ABSOLUTE:
					// skip relocation
					break;

				case IMAGE_REL_BASED_HIGHLOW:
					// change complete 32 bit address
					patchAddrHL = (DWORD *)(dest + offset);
					*patchAddrHL += (DWORD)delta;
					break;

#ifdef _WIN64
				case IMAGE_REL_BASED_DIR64:
					patchAddr64 = (ULONGLONG *)(dest + offset);
					*patchAddr64 += delta;
					break;
#endif

				default:
					ret = false;
					break;
				}
			}

			if (ret)
			{
				remainSize -= pBaseReloc[0].SizeOfBlock;
				pBaseReloc = (IMAGE_BASE_RELOCATION *)((char*)pBaseReloc + pBaseReloc[0].SizeOfBlock);
			}
		}

		return ret;

	}

	bool DoImport(unsigned char *codeBase, IMAGE_IMPORT_DESCRIPTOR *pImportDesc)
	{
		bool ret = true;

		while (pImportDesc[0].Name)
		{
			char *szLibName = (char*)codeBase + pImportDesc[0].Name;

			HMODULE hLib = LoadLib(szLibName);

			if (!hLib)
			{
				LogErr("Can't load library [%d]", szLibName);
				ret = false;
				break;
			}

			POINTER_TYPE *thunkRef;
			FARPROC *funcRef;
			if (pImportDesc[0].OriginalFirstThunk) {
				thunkRef = (POINTER_TYPE *)(codeBase + pImportDesc[0].OriginalFirstThunk);
				funcRef = (FARPROC *)(codeBase + pImportDesc[0].FirstThunk);
			}
			else {
				// no hint table
				thunkRef = (POINTER_TYPE *)(codeBase + pImportDesc[0].FirstThunk);
				funcRef = (FARPROC *)(codeBase + pImportDesc[0].FirstThunk);
			}

			if (!thunkRef || !funcRef)
			{
				ret = false;
				break;
			}
			else for (; *thunkRef; thunkRef++, funcRef++)
			{
				*funcRef = 0;
				if (IMAGE_SNAP_BY_ORDINAL(*thunkRef))
				{
					//*funcRef = GetProcAddress(hLib, (LPCSTR)IMAGE_ORDINAL(*thunkRef));
					// not support yet
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)(codeBase + (*thunkRef));

					*funcRef = GetLibFunAddress(hLib, (LPCSTR)&thunkData->Name);
					if (*funcRef == 0)
					{
						LogErr("Can't get function [%s]:[%s]", szLibName, (LPCSTR)&thunkData->Name);
					}
				}

				if (*funcRef == 0) 
				{
					ret = false;
					break;
				}
			}

			pImportDesc++;
		}

		return ret;
	}

	FARPROC DoGetProcAddress(unsigned char *codeBase, PIMAGE_EXPORT_DIRECTORY pExport, const char *szProc)
	{
		void* ret = nullptr;

		WORD *pwExportOrd = (WORD*)(codeBase + pExport->AddressOfNameOrdinals);
		DWORD *pdwExportAddr = (DWORD*)(codeBase + pExport->AddressOfFunctions);
		DWORD *pdwExportName = (DWORD*)(codeBase + pExport->AddressOfNames);

		DWORD i, n = pExport->NumberOfNames;
		for (i = 0; i < n; ++i)
		{
			const char *pszExpFuncName = (char*)codeBase + pdwExportName[i];
			if (strcmp(szProc, pszExpFuncName) == 0)
			{
				ret = codeBase + pdwExportAddr[pwExportOrd[i]];
				break;
			}
		}

		return (FARPROC)ret;
	}

	bool PECheck(const void *pImg, int sztImg)
	{
		bool ret = false;
		IMAGE_DOS_HEADER *pDos = (IMAGE_DOS_HEADER*)pImg;
		IMAGE_NT_HEADERS *pNT = (IMAGE_NT_HEADERS*)((char*)pImg + pDos->e_lfanew);

		WORD wMagic =
#ifndef _WIN64
			IMAGE_NT_OPTIONAL_HDR32_MAGIC;
#else
			IMAGE_NT_OPTIONAL_HDR64_MAGIC;
#endif

		WORD wMachine =
#ifndef _WIN64
			IMAGE_FILE_MACHINE_I386;
#else
			IMAGE_FILE_MACHINE_AMD64;
#endif
		if ((ULONG)pDos->e_lfanew + pNT->FileHeader.SizeOfOptionalHeader >= (ULONG)sztImg)
		{
			LogErr("Invalid PE Header size");
		}
		if (pNT->Signature != IMAGE_NT_SIGNATURE)
		{
			LogErr("Invalid PE Signature");
		}
		else if (pNT->OptionalHeader.Magic != wMagic
			|| pNT->FileHeader.Machine != wMachine)
		{
			LogErr("Invalid PE Machine");
		}
		else if (pNT->FileHeader.NumberOfSections >= 90)
		{
			LogErr("Number of PE Section %d >= %d", pNT->FileHeader.NumberOfSections, 90);
		}
		else if (pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0)
		{
			LogErr("Not support image with no relocation yet!");
		}
		else
		{
			ret = true;
		}

		return ret;

	}

	HMODULE FixIntoMem(const void *pImg, int sztImg)
	{
		HMODULE hMod = nullptr;

		const IMAGE_DOS_HEADER *pDos = (const IMAGE_DOS_HEADER*)pImg;
		char *pChOldDos = (char*)pDos;

		IMAGE_NT_HEADERS *pOldNTHead = (IMAGE_NT_HEADERS*)((char*)pImg + pDos->e_lfanew);
		DWORD dwFullNTSize = sizeof(IMAGE_NT_HEADERS) - (sizeof(IMAGE_OPTIONAL_HEADER) - pOldNTHead->FileHeader.SizeOfOptionalHeader);
		IMAGE_SECTION_HEADER *pOldSectHead = (IMAGE_SECTION_HEADER*)((char*)pOldNTHead + dwFullNTSize);

		if (pOldNTHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0
			&& (pOldNTHead->FileHeader.Characteristics&IMAGE_FILE_RELOCS_STRIPPED)
			)
		{
			hMod = (HMODULE)pOldNTHead->OptionalHeader.ImageBase;
		}

		hMod = (HMODULE)Common::MemAlloc(hMod, pOldNTHead->OptionalHeader.SizeOfImage, Common::EMemProtect::MemProtect_ReadWriteExec);
		if (hMod == nullptr)
		{
			LogErr("Can't alloc memory: %d at %p", pOldNTHead->OptionalHeader.SizeOfImage, hMod);
		}
		else
		{
			IMAGE_DOS_HEADER *pNewDos = (IMAGE_DOS_HEADER*)hMod;
			char *pChNewDos = (char*)hMod;

			DWORD dwStubSize = dwFullNTSize + sizeof(IMAGE_SECTION_HEADER)*pOldNTHead->FileHeader.NumberOfSections;
			//copy dos
			memcpy(pChNewDos, pChOldDos, pDos->e_lfanew);

			IMAGE_NT_HEADERS *pNewNtHead = (IMAGE_NT_HEADERS*)(pChNewDos + pDos->e_lfanew);
			//copy NT head & section header
			memcpy(pNewNtHead, pOldNTHead, dwStubSize);

			//fix all section 
			int iSectionIndex = 0;
			for (iSectionIndex = 0;
				iSectionIndex < pOldNTHead->FileHeader.NumberOfSections;
				++iSectionIndex)
			{
				char *pNewSectData = pChNewDos + pOldSectHead[iSectionIndex].VirtualAddress;
				char *pOldSectData = pChOldDos + pOldSectHead[iSectionIndex].PointerToRawData;

				//check for valid section data
				if (pOldSectHead[iSectionIndex].SizeOfRawData
					&& pOldSectHead[iSectionIndex].PointerToRawData + pOldSectHead[iSectionIndex].SizeOfRawData > (ULONG)sztImg)
				{
					break;
				}

				DWORD dwRVASize = Align(pOldSectHead[iSectionIndex].Misc.VirtualSize, pOldNTHead->OptionalHeader.SectionAlignment);
				memcpy(pNewSectData, pOldSectData, pOldSectHead[iSectionIndex].SizeOfRawData);
			}

			if (iSectionIndex == pOldNTHead->FileHeader.NumberOfSections)
			{
			}
			else
			{
				Common::MemFree(hMod); hMod = nullptr;
			}
		}

		return (HMODULE)hMod;
	}

	bool Reloc(HMODULE hMod)
	{
		bool ret = false;

		IMAGE_DOS_HEADER *pDos = (IMAGE_DOS_HEADER*)hMod;
		unsigned char *pBase = (unsigned char*)pDos;

		IMAGE_NT_HEADERS *pNTHead = (IMAGE_NT_HEADERS*)((char*)pDos + pDos->e_lfanew);
		IMAGE_DATA_DIRECTORY imgDirRelocation = pNTHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

		unsigned char *pOrgBase = (unsigned char*)pNTHead->OptionalHeader.ImageBase;
		if (pOrgBase == pBase)
		{
			ret = true;
		}
		else if (imgDirRelocation.VirtualAddress == 0)
		{
			ret = false;
		}
		else
		{
			size_t delta = pBase - pOrgBase;

			IMAGE_BASE_RELOCATION *pBaseReloc = (IMAGE_BASE_RELOCATION*)(pBase + imgDirRelocation.VirtualAddress);

			if (imgDirRelocation.VirtualAddress + imgDirRelocation.Size >= pNTHead->OptionalHeader.SizeOfImage)
			{
				ret = false;
			}
			else
			{
				ret = DoBaseReloc(pBase, pNTHead->OptionalHeader.SizeOfImage, delta, pBaseReloc, imgDirRelocation.Size);
			}
		}

		return ret;
	}

	bool Import(HMODULE hMod)
	{
		bool ret = true;

		IMAGE_DOS_HEADER *pDos = (IMAGE_DOS_HEADER*)hMod;
		unsigned char *pBase = (unsigned char*)hMod;

		IMAGE_NT_HEADERS *pNTHead = (IMAGE_NT_HEADERS*)(pBase + pDos->e_lfanew);
		IMAGE_DATA_DIRECTORY imgDirImport = pNTHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

		if (imgDirImport.VirtualAddress)
		{
			IMAGE_IMPORT_DESCRIPTOR *pImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)(pBase + imgDirImport.VirtualAddress);
			if (imgDirImport.VirtualAddress + imgDirImport.Size >= pNTHead->OptionalHeader.SizeOfImage)
			{
				ret = false;
			}
			else
			{
				ret = DoImport(pBase, pImportDesc);
			}
		}

		return ret;
	}

	bool ExecuteTLS(HMODULE hMod)
	{
		unsigned char *codeBase = (unsigned char *)hMod;
		PIMAGE_TLS_DIRECTORY tls;
		PIMAGE_TLS_CALLBACK* callback;

		IMAGE_DOS_HEADER *pDos = (IMAGE_DOS_HEADER*)codeBase;
		IMAGE_NT_HEADERS *pNTHead = (IMAGE_NT_HEADERS*)(codeBase + pDos->e_lfanew);
		PIMAGE_DATA_DIRECTORY directory = &pNTHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
		if (directory->VirtualAddress == 0) {
			return true;
		}

		tls = (PIMAGE_TLS_DIRECTORY)(codeBase + directory->VirtualAddress);
		callback = (PIMAGE_TLS_CALLBACK *)tls->AddressOfCallBacks;
		if (callback) {
			while (*callback) {
				(*callback)((LPVOID)codeBase, DLL_PROCESS_ATTACH, NULL);
				callback++;
			}
		}
		return true;
	}

	HMODULE Load(const void * ppe, int sztPe)
	{
		HMODULE hMod = FixIntoMem(ppe, sztPe);
		if (hMod
			&& Reloc(hMod)
			&& Import(hMod)
			&& ExecuteTLS(hMod))
		{
			IMAGE_DOS_HEADER *pDos = (IMAGE_DOS_HEADER*)hMod;
			IMAGE_NT_HEADERS *pNTHead = (IMAGE_NT_HEADERS*)((char*)hMod + pDos->e_lfanew);

			char *pEntry = (char*)hMod + pNTHead->OptionalHeader.AddressOfEntryPoint;

			if ((pNTHead->FileHeader.Characteristics&IMAGE_FILE_DLL) == 0)
			{
				int(WINAPI *iExeMain)(void);
				*(char **)&iExeMain = pEntry;

				iExeMain();
			}
			else
			{
				bool(WINAPI *iDllMain)(void*, unsigned int, void*);
				*(char **)&iDllMain = pEntry;

				if (iDllMain(hMod, DLL_PROCESS_ATTACH, nullptr))
				{
					LogErr("LoadDll failed");
					Release(hMod);
				}
			}
		}

		return hMod;
	}

	FARPROC GetFuncAddress(HMODULE hMod, const char * szProc)
	{
		FARPROC ret = nullptr;

		IMAGE_DOS_HEADER *pDos = (IMAGE_DOS_HEADER*)hMod;
		unsigned char *pBase = (unsigned char*)hMod;

		IMAGE_NT_HEADERS *pNTHead = (IMAGE_NT_HEADERS*)(pBase + pDos->e_lfanew);
		IMAGE_DATA_DIRECTORY imgDirImport = pNTHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

		if (imgDirImport.VirtualAddress)
		{
			IMAGE_EXPORT_DIRECTORY *pExportDesc = (IMAGE_EXPORT_DIRECTORY*)(pBase + imgDirImport.VirtualAddress);
			if (imgDirImport.VirtualAddress + imgDirImport.Size >= pNTHead->OptionalHeader.SizeOfImage)
			{
			}
			else
			{
				ret = DoGetProcAddress(pBase, pExportDesc, szProc);
			}
		}

		return ret;
	}

	void Release(HMODULE hMod)
	{
		if (hMod != nullptr)
		{
			IMAGE_DOS_HEADER *pDos = (IMAGE_DOS_HEADER*)hMod;
			IMAGE_NT_HEADERS *pNTHead = (IMAGE_NT_HEADERS*)((char*)hMod + pDos->e_lfanew);

			char *pEntry = (char*)hMod + pNTHead->OptionalHeader.AddressOfEntryPoint;

			if ((pNTHead->FileHeader.Characteristics&IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
			{
				bool(WINAPI *iDllMain)(void*, unsigned int, void*);
				*(char **)&iDllMain = pEntry;

				LogInf("Call DllMain");
				iDllMain(hMod, DLL_PROCESS_DETACH, 0);
			}

			Common::MemFree(hMod);
		}
	}

}


