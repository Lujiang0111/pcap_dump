#include "lib_log.h"

PCAP_DUMP_BEGIN_NAMESPACE

static void DefaultLogCallback(void *opaque, LogLevels level, const char *file_name, int file_line, const char *content, size_t len)
{
    lccl::log::Levels lccl_level = lccl::log::Levels::kDebug;
    switch (level)
    {
    case LogLevels::kDebug:
        lccl_level = lccl::log::Levels::kDebug;
        break;
    case LogLevels::kInfo:
        lccl_level = lccl::log::Levels::kInfo;
        break;
    case LogLevels::kWarn:
        lccl_level = lccl::log::Levels::kWarn;
        break;
    case LogLevels::kError:
        lccl_level = lccl::log::Levels::kError;
        break;
    default:
        return;
    }

    fmt::println("[pcap_dump]: {} {}:{} {:.{}}",
        lccl::log::LevelToString(lccl_level),
        file_name, file_line,
        content, len);
}

static void (*lib_log_cb)(void *opaque, LogLevels level, const char *file_name, int file_line, const char *content, size_t len) = DefaultLogCallback;
static void *lib_log_opaque = nullptr;

void SetLogCallback(
    void (*cb)(void *opaque, LogLevels level, const char *file_name, int file_line, const char *content, size_t len),
    void *opaque)
{
    lib_log_cb = (cb) ? cb : DefaultLogCallback;
    lib_log_opaque = opaque;
}

void LibLogContent(LogLevels level, const char *file_name, int file_line, const char *content, size_t len)
{
    lib_log_cb(lib_log_opaque, level, file_name, file_line, content, len);
}

PCAP_DUMP_END_NAMESPACE
