
#pragma once

#include <string>
#include <stdint.h>

#define ParamIn
#define ParamInOpt
#define ParamOut
#define ParamOutOpt
#define ParamInOut

#define ParamRelate(paramName)

#define DivUp(a,b) ((a+b-1)/(b))

#define Align(a,b) (DivUp(a,b)*(b))
#define DAlign(a,b) (((a)/(b))*(b))

#define cmin(a,b) (a)<(b)?(a):(b)

#ifdef __GNUC__
#define __debugbreak __builtin_trap
#endif

namespace Common
{
	extern const std::string newline;

	std::string ToString(int val);
	std::string ToString(unsigned int val);
	std::string ToString(int64_t val);
	std::string ToString(uint64_t val);
	std::string ToString(const char *val);
	std::string ToString(const std::string &val);
	std::string ToString(const std::wstring &val);
	std::string ToString(const std::string &fmt, ...);

	bool ToVal(const std::string &strval, int &val);
	bool ToVal(const std::string &strval, unsigned int &val);
	bool ToVal(const std::string &strval, int64_t &val);
	bool ToVal(const std::string &strval, uint64_t &val);

	int GetVal(const std::string &strval, int onfailed);
	
	std::string ToUpper(const std::string &str);
	std::string ToLower(const std::string &str);

#define SLEEP_MINIUM	1
	void mSleep(int miliSecond);

	enum EMemProtect
	{
		MemProtect_Read,
		MemProtect_ReadWrite,
		MemProtect_ReadWriteExec,
		MemProtect_Exec,
	};

	void * MemAlloc(void *pBase, int sztMem, EMemProtect protect);
	bool MemGetProtect(void *pMem, EMemProtect &protect);
	bool MemSetProtect(void *pMem, int sztMem, EMemProtect protect);
	void MemFree(void *pMem);
}