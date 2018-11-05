
#include "common.h"

#ifdef _WIN32
#include <windows.h>
#elif __linux
#include <unistd.h>
#include <sys/mman.h>
#endif


#include <locale>
#include <codecvt>
#include <stdarg.h>

namespace Common
{
	const std::string newline = "\r\n";

	std::string ToString(int val)
	{
		char intBuf[40];
		sprintf(intBuf, "%d", val);
		return intBuf;
	}

	std::string ToString(unsigned int val)
	{
		char intBuf[40];
		sprintf(intBuf, "%u", val);
		return intBuf;
	}

	std::string ToString(int64_t val)
	{
		char intBuf[80];
		sprintf(intBuf, "%lld", val);
		return intBuf;
	}

	std::string ToString(const char *val)
	{
		std::string ret;
		if (val == nullptr)
		{
			ret = "(null)";
		}
		else
		{
			ret= val;
		}

		return ret;
	}

	std::string ToString(uint64_t val)
	{
		char intBuf[80];
		sprintf(intBuf, "%llu", val);
		return intBuf;
	}

	std::string ToString(const std::string &val)
	{
		return val;
	}

	std::string ToString(const std::wstring &val)
	{
		using convert_typeX = std::codecvt_utf8 < wchar_t >;
		std::wstring_convert<convert_typeX, wchar_t> converterX;

		return converterX.to_bytes(val);
	}


	std::string ToString(const std::string &fmt, ...)
	{
		char buffer[0x1000];
		va_list va;

		const char * cfmt = fmt.c_str();
		va_start(va, cfmt);
		vsnprintf(buffer, sizeof(buffer), fmt.c_str(), va);
		va_end(va);

		return buffer;
	}

	bool ToVal(const std::string &strval, int &val)
	{
		return sscanf(strval.c_str(), "%d", &val) > 0;
	}

	bool ToVal(const std::string &strval, unsigned int &val)
	{
		return sscanf(strval.c_str(), "%u", &val) > 0;
	}

	bool ToVal(const std::string &strval, int64_t &val)
	{
		return sscanf(strval.c_str(), "%lld", &val) > 0;
	}

	bool ToVal(const std::string &strval, uint64_t &val)
	{
		return sscanf(strval.c_str(), "%llu", &val) > 0;
	}

	int GetVal(const std::string &strval, int onfailed)
	{
		ToVal(strval, onfailed);
		return onfailed;
	}


	std::string ToUpper(const std::string &str)
	{
		std::string ret = str;
		for (std::string::iterator c = ret.begin(); c != ret.end(); ++c) *c = toupper(*c);

		return ret;
	}

	std::string ToLower(const std::string &str)
	{
		std::string ret = str;
		for (std::string::iterator c = ret.begin(); c != ret.end(); ++c) *c = tolower(*c);

		return ret;
	}

#ifdef _WIN32
	void mSleep(int miliSecond)
	{
		Sleep(miliSecond);
	}

	DWORD GetProtect(EMemProtect protect)
	{
		DWORD dwProtect = 0;
		switch (protect)
		{
		case Common::MemProtect_Read:
			dwProtect = PAGE_READONLY;
			break;

		case Common::MemProtect_ReadWrite:
			dwProtect = PAGE_READWRITE;
			break;

		case Common::MemProtect_ReadWriteExec:
			dwProtect = PAGE_EXECUTE_READWRITE;
			break;

		case Common::MemProtect_Exec:
			dwProtect = PAGE_EXECUTE;
			break;

		default:
			__debugbreak();
			break;
		}

		return dwProtect;
	}

	void * MemAlloc(void *pBase, int sztMem, EMemProtect protect)
	{
		void* ret = nullptr;
		ret = VirtualAlloc(pBase, sztMem, MEM_COMMIT | MEM_RESERVE, GetProtect(protect));
		return ret;
	}

	bool MemGetProtect(void *pMem, EMemProtect &protect)
	{
		bool ret = false;

		MEMORY_BASIC_INFORMATION memInfor;
		if (VirtualQuery(pMem, &memInfor, sizeof(memInfor)) > 0)
		{
			ret = true;
			switch (memInfor.Protect)
			{
			case PAGE_READONLY:
				protect = MemProtect_Read;
				break;

			case PAGE_READWRITE:
				protect = MemProtect_ReadWrite;
				break;

			case PAGE_EXECUTE_READWRITE:
				protect = MemProtect_ReadWriteExec;
				break;

			case PAGE_EXECUTE:
				protect = MemProtect_Exec;
				break;

			default:
				ret = false;
				break;
			}
		}

		return ret;
	}

	bool MemSetProtect(void *pMem, int sztMem, EMemProtect protect)
	{
		bool ret = false;
		DWORD dwOld;
		if (VirtualProtect(pMem, sztMem, GetProtect(protect), &dwOld))
		{
			ret = true;
		}

		return ret;
	}

	void MemFree(void *pMem)
	{
		VirtualFree(pMem, 0, MEM_RELEASE);
	}

#elif __linux
	void mSleep(int miliSecond)
	{
		usleep(miliSecond * 1000);
	}

	int GetProtect(EMemProtect protect)
	{
		int iProtect = 0;
		switch (protect)
		{
		case Common::MemProtect_Read:
			iProtect = PROT_READ;
			break;

		case Common::MemProtect_ReadWrite:
			iProtect = PROT_READ | PROT_WRITE;
			break;

		case Common::MemProtect_ReadWriteExec:
			iProtect = PROT_READ | PROT_WRITE | PROT_EXEC;
			break;

		case Common::MemProtect_Exec:
			iProtect = PROT_EXEC;
			break;

		default:
			__debugbreak();
			break;
		}

		return iProtect;
	}

	void * MemAlloc(void *pBase
	, int sztMem, EMemProtect protect)
	{
		void* ret = nullptr;
		ret = mmap(pBase, sztMem, GetProtect(protect), MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if (ret == (void *) -1)
		{
			int err = errno;
			ret = 0;
		}
		return ret;
	}

	bool MemGetProtect(void *pMem, EMemProtect &protect)
	{
		bool ret = false;

		return ret;
	}

	bool MemSetProtect(void *pMem, int sztMem, EMemProtect protect)
	{
		bool ret = false;
		if (mprotect(pMem, sztMem, GetProtect(protect)) == 0)
		{
			ret = true;
		}

		return ret;
	}

	void MemFree(void *pMem)
	{
		munmap(pMem, 0);
	}

#endif

}