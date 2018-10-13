
#pragma once

#include <string>

enum ELogLevel
{
	LogLevel_Info,
	LogLevel_Trace,
	LogLevel_Debug,
	LogLevel_Warn,
	LogLevel_Error,

	LogLevel_Max // no log
};

typedef void(*LogCallbackFunc)(ELogLevel lv, const std::string &log, void *param);

#ifdef _USE_LOG_

bool LogInitConsole(ELogLevel outLevel);
bool LogInitFile(ELogLevel outLevel, const char *szFile);
bool LogInitCallback(ELogLevel outLevel, LogCallbackFunc cb, void *cbParam);

namespace Common
{
	void Log(ELogLevel lv,
		const std::string &sourceFile,
		const std::string &function, int atLine,
		const char *msgFormat, ...);
}

#define LogInf(msgFormat, ...)	Common::Log(LogLevel_Info, __FILE__, __FUNCTION__, __LINE__, msgFormat, ##__VA_ARGS__)
#define LogTraEnter	Common::Log(LogLevel_Trace, __FILE__, __FUNCTION__, __LINE__, "Enter");
#define LogTraLeave	Common::Log(LogLevel_Trace, __FILE__, __FUNCTION__, __LINE__, "Leave");
#define LogDbg(msgFormat, ...)	Common::Log(LogLevel_Debug, __FILE__, __FUNCTION__, __LINE__, msgFormat, ##__VA_ARGS__)
#define LogWrn(msgFormat, ...)	Common::Log(LogLevel_Warn, __FILE__, __FUNCTION__, __LINE__, msgFormat, ##__VA_ARGS__)
#define LogErr(msgFormat, ...)	Common::Log(LogLevel_Error, __FILE__, __FUNCTION__, __LINE__, msgFormat, ##__VA_ARGS__)

#else

#define LogInitConsole(...) true
#define LogInitFile(...) true
#define LogInitCallback(...) true

#define LogInf(msgFormat, ...)
#define LogTraEnter ;
#define LogTraLeave ;
#define LogDbg(msgFormat, ...)
#define LogWrn(msgFormat, ...)
#define LogErr(msgFormat, ...)

#endif
