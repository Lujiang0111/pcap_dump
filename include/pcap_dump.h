#ifndef LIBPCAP_DUMP_INCLUDE_PCAP_DUMP_H_
#define LIBPCAP_DUMP_INCLUDE_PCAP_DUMP_H_

#include <cstdint>
#include <cstddef>
#include <memory>

#if defined(_MSC_VER)
#if defined(LIBPCAP_DUMP_API_EXPORT)
#define LIBPCAP_DUMP_API __declspec(dllexport)
#else
#define LIBPCAP_DUMP_API __declspec(dllimport)
#endif
#else
#define LIBPCAP_DUMP_API
#endif

#define PCAP_DUMP_BEGIN_NAMESPACE namespace pcapdump {
#define PCAP_DUMP_END_NAMESPACE }

PCAP_DUMP_BEGIN_NAMESPACE

enum class LogLevels
{
    kDebug = 0,
    kInfo,
    kWarn,
    kError,
    kNb,
};

// 库日志回调
LIBPCAP_DUMP_API void SetLogCallback(
    void (*cb)(void *opaque, LogLevels level, const char *file_name, int file_line, const char *content, size_t len),
    void *opaque);

class IDumper
{
public:
    enum class ParamNames
    {
        kIp = 0,            // char *
        kPort,              // char *, Port string or any
        kInterface,         // char *, Interface IP or Name
        kPromisc,           // bool
        kSegmentInterval,   // int64_t
        kSegmentSize,       // size_t
        kDumpDir,           // char *
        kNb,
    };

public:
    virtual ~IDumper() = default;

    virtual bool SetParam(ParamNames param_name, const void *val, size_t size) = 0;

    virtual bool Init() = 0;
    virtual void Deinit() = 0;
};

LIBPCAP_DUMP_API std::shared_ptr<IDumper> CreateDumper();

PCAP_DUMP_END_NAMESPACE

#endif // !LIBPCAP_DUMP_INCLUDE_PCAP_DUMP_H_
