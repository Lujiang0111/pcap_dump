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

#define PCAP_DUMP_NAMESPACE_BEGIN namespace pcapdump {
#define PCAP_DUMP_NAMESPACE_END }

PCAP_DUMP_NAMESPACE_BEGIN

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
        kIp = 0,            // char *   IP字符串
        kPort,              // char *   端口字符串
        kInterface,         // char *   网卡IP或名称
        kPromisc,           // bool     是否开启混杂
        kIoFlag,            // int      抓取输入或输出，可以用|多选，1：只抓输入，2：只抓输出
        kSegmentInterval,   // int64_t  0代表不分片
        kSegmentSize,       // size_t   切片循环个数, 0代表无限
        kDumpDir,           // char *   录制文件夹
        kDumpName,          // char *   切片名称，仅在不分片情况下生效
        kNb,
    };

public:
    virtual ~IDumper() = default;

    virtual bool SetParam(ParamNames param_name, const void *val, size_t size) = 0;

    virtual bool Init() = 0;
    virtual void Deinit() = 0;
};

LIBPCAP_DUMP_API std::shared_ptr<IDumper> CreateDumper();

PCAP_DUMP_NAMESPACE_END

#endif // !LIBPCAP_DUMP_INCLUDE_PCAP_DUMP_H_
