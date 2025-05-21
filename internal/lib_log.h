#ifndef LIBPCAP_DUMPER_INTERNAL_LIB_LOG_H_
#define LIBPCAP_DUMPER_INTERNAL_LIB_LOG_H_

#include "lccl/log.h"
#include "pcap_dump.h"

PCAP_DUMP_BEGIN_NAMESPACE

void LibLogContent(LogLevels level, const char *file_name, int file_line, const char *content, size_t len);

template<typename... Args>
inline void LibLogFmt(LogLevels level, const char *file_name, int file_line, fmt::format_string<Args...> fmt, Args &&... args)
{
    std::string content = fmt::vformat(fmt, fmt::make_format_args(args...));
    LibLogContent(level, file_name, file_line, content.c_str(), content.length());
}

PCAP_DUMP_END_NAMESPACE

#define LIB_LOG(level, fmt, ...) pcapdump::LibLogFmt(level, __FILE__, __LINE__, fmt, ##__VA_ARGS__);

#endif // !LIBPCAP_DUMPER_INTERNAL_LIB_LOG_H_
