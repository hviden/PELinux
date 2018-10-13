
#ifdef _USE_LOG_

#include "log.h"
#include "common.h"
#include <stdarg.h>
#include <time.h>

#include <iostream>
#include <fstream>

namespace Common
{
	bool bHasInit = false;
	ELogLevel outLevel = LogLevel_Max; // no log
	LogCallbackFunc logCb = nullptr;
	void *logCbParam = nullptr;

	class LogOut
	{
	private:
		std::mutex lock;
		FILE *out;

		void InitDefault()
		{
			
		}

	public:
		LogOut()// console
		{
			InitDefault();
			out = stdout;
		}

		LogOut(const char * szFile)// file
		{
			InitDefault();
			out = fopen(szFile, "wb");
		}

		void Log(const std::string &log)
		{
			lock.lock();
			fwrite(log.c_str(), log.length(), 1, this->out);
			fprintf(this->out, "\n");
			lock.unlock();
		}

		~LogOut()
		{
			fclose(this->out);
		}
	};

	void LogOutFunc(ELogLevel lv, const std::string &log, void *param)
	{
		LogOut * pLog = (LogOut*)param;
		pLog->Log(log);
	}

	const std::string LogLevel2String(ELogLevel lv)
	{
		const char *ret = "[UNK]";
		switch (lv)
		{
		case LogLevel_Info:
			ret = "[INF]";
			break;

		case LogLevel_Trace:
			ret = "[TRA]";
			break;

		case LogLevel_Debug:
			ret = "[DBG]";
			break;

		case LogLevel_Warn:
			ret = "[WRN]";
			break;

		case LogLevel_Error:
			ret = "[ERR]";
			break;
		
		default:
			__debugbreak();
			break;
		}

		return ret;
	}
	
	void Log(ELogLevel lv,
		const std::string &sourceFile, const std::string &function, int atLine,
		const char *msgFormat, ...)
	{
		if (lv >= outLevel)
		{
			char msgBuffer[0x1000];//4kb log length

			// format time
			time_t now = time(NULL);
			strftime(msgBuffer, sizeof(msgBuffer), "[%X]", localtime(&now));

			// log header
			std::string log = LogLevel2String(lv) + "[" + sourceFile + "::" + function + "::" + ToString(atLine) + "]" + std::string(msgBuffer);

			// build log message
			va_list va;
			va_start(va, msgFormat);

			msgBuffer[sizeof(msgBuffer) - 1] = 0;
			vsnprintf(msgBuffer, sizeof(msgBuffer) - 1, msgFormat, va);

			va_end(va);

			log += msgBuffer;

			// callback
			logCb(lv, log, logCbParam);
		}
	}
}

bool LogInitConsole(ELogLevel outLevel)
{
	Common::LogOut * pLog = new Common::LogOut();
	return LogInitCallback(outLevel, Common::LogOutFunc, pLog);
}

bool LogInitFile(ELogLevel outLevel, const char *szFile)
{
	Common::LogOut * pLog = new Common::LogOut(szFile);
	return LogInitCallback(outLevel, Common::LogOutFunc, pLog);
}

bool LogInitCallback(ELogLevel outLevel, LogCallbackFunc cb, void *cbParam)
{
	bool ret = false;

	if (!Common::bHasInit)
	{
		Common::outLevel = outLevel;
		Common::logCb = cb;
		Common::logCbParam = cbParam;

		ret = Common::bHasInit = true;
	}

	return ret;
}

#endif