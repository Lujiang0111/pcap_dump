#include <sstream>
#include "lccl/file.h"
#include "lccl/log.h"
#include "lccl/socket.h"
#include "lccl/utils/path_utils.h"
#include "dumper.h"
#include "lib_log.h"

PCAP_DUMP_BEGIN_NAMESPACE

Dumper::Dumper() :
    work_thread_running_(false),
    work_thread_state_(WorkThreadStates::kInit),
    pcap_(nullptr),
    pcap_link_type_(DLT_NULL),
    pcap_tstamp_precision_(1),
    pcap_dumper_(nullptr),
    pcap_dumper_prev_time_(0),
    file_name_idx_(0)
{
    in_params_.assign(static_cast<size_t>(ParamNames::kNb), nullptr);
    memset(&pcap_bfp_, 0, sizeof(pcap_bfp_));
}

Dumper::~Dumper()
{
    Deinit();
}

bool Dumper::SetParam(ParamNames param_name, const void *val, size_t size)
{
    if (val)
    {
        std::shared_ptr<std::vector<uint8_t>> data = std::make_shared<std::vector<uint8_t>>(size);
        memcpy(data->data(), val, size);
        in_params_[static_cast<size_t>(param_name)] = data;
    }
    else
    {
        in_params_[static_cast<size_t>(param_name)] = nullptr;
    }
    
    return true;
}

bool Dumper::Init()
{
    if (!ParseParam())
    {
        return false;
    }

    time_t curr_time = time(nullptr);
    std::tm time_tm;
#if defined(_MSC_VER)
    ::localtime_s(&time_tm, &curr_time);
#else
    ::localtime_r(&curr_time, &time_tm);
#endif

    file_dir_name_ = lccl::OsPathJoin(param_->dump_dir, fmt::format("{}_{}_{}_{:04}{:02}{:02}_{:02}{:02}{:02}",
        param_->ip, param_->port, param_->interface_name,
        time_tm.tm_year + 1900,
        time_tm.tm_mon + 1,
        time_tm.tm_mday,
        time_tm.tm_hour,
        time_tm.tm_min,
        time_tm.tm_sec));
    lccl::file::CreateDir(file_dir_name_.c_str(), false);

    work_thread_running_ = true;
    work_thread_ = std::thread(&Dumper::WorkThread, this);
    return true;
}

void Dumper::Deinit()
{
    {
        std::lock_guard<std::mutex> lock(work_thread_wait_mutex_);
        work_thread_running_ = false;
    }
    work_thread_wait_cond_.notify_all();

    if (work_thread_.joinable())
    {
        work_thread_.join();
    }

    param_ = nullptr;
    in_params_.assign(static_cast<size_t>(ParamNames::kNb), nullptr);
}

static std::string DeviceIpToName(const std::string &device_ip)
{
    std::shared_ptr<lccl::skt::IAddr> device_addr = lccl::skt::CreateAddr(device_ip.c_str(), 0, true);
    if (!device_addr)
    {
        return "any";
    }

    sockaddr *device_sa = device_addr->GetNative();

    std::vector<char> pcap_errbuf(PCAP_ERRBUF_SIZE);
    pcap_if_t *all_devices = nullptr;
    pcap_findalldevs(&all_devices, &pcap_errbuf[0]);
    for (pcap_if_t *curr_device = all_devices; curr_device; curr_device = curr_device->next)
    {
        for (pcap_addr *curr_pcap_addr = curr_device->addresses; curr_pcap_addr; curr_pcap_addr = curr_pcap_addr->next)
        {
            if (0 == lccl::skt::CompareSa(device_sa, curr_pcap_addr->addr))
            {
                std::string device_name = curr_device->name;
                pcap_freealldevs(all_devices);
                return device_name;
            }
        }
    }
    pcap_freealldevs(all_devices);

    return "any";
}

bool Dumper::ParseParam()
{
    param_ = std::make_shared<Param>();

    param_->ip = (in_params_[static_cast<size_t>(ParamNames::kIp)])
        ? std::string(reinterpret_cast<char *>(in_params_[static_cast<size_t>(ParamNames::kIp)]->data()), in_params_[static_cast<size_t>(ParamNames::kIp)]->size())
        : "any";

    param_->port = (in_params_[static_cast<size_t>(ParamNames::kPort)])
        ? std::string(reinterpret_cast<char *>(in_params_[static_cast<size_t>(ParamNames::kPort)]->data()), in_params_[static_cast<size_t>(ParamNames::kPort)]->size())
        : "any";

    param_->interface_name = (in_params_[static_cast<size_t>(ParamNames::kInterface)])
        ? std::string(reinterpret_cast<char *>(in_params_[static_cast<size_t>(ParamNames::kInterface)]->data()), in_params_[static_cast<size_t>(ParamNames::kInterface)]->size())
        : "any";
    lccl::skt::AddrTypes addr_type = lccl::skt::GetIpType(param_->interface_name.c_str());
    switch (addr_type)
    {
    case lccl::skt::AddrTypes::kIpv4:
    case lccl::skt::AddrTypes::kIpv6:
        param_->interface_device = DeviceIpToName(param_->interface_name);
        break;
    default:
        param_->interface_device = param_->interface_name;
        break;
    }

    param_->promisc = (in_params_[static_cast<size_t>(ParamNames::kPromisc)])
        ? *reinterpret_cast<bool *>(in_params_[static_cast<size_t>(ParamNames::kPromisc)]->data())
        : false;
    param_->segment_interval = (in_params_[static_cast<size_t>(ParamNames::kSegmentInterval)])
        ? *reinterpret_cast<int64_t *>(in_params_[static_cast<size_t>(ParamNames::kSegmentInterval)]->data())
        : 30;
    param_->segment_size = (in_params_[static_cast<size_t>(ParamNames::kSegmentSize)])
        ? *reinterpret_cast<size_t *>(in_params_[static_cast<size_t>(ParamNames::kSegmentSize)]->data())
        : 10;

    param_->dump_dir = (in_params_[static_cast<size_t>(ParamNames::kDumpDir)])
        ? std::string(reinterpret_cast<char *>(in_params_[static_cast<size_t>(ParamNames::kDumpDir)]->data()), in_params_[static_cast<size_t>(ParamNames::kDumpDir)]->size())
        : "dump";

    return true;
}

void Dumper::WorkThread()
{
    work_thread_state_ = WorkThreadStates::kDeinit;
    while (work_thread_running_)
    {
        work_thread_state_ret_.new_state = work_thread_state_;
        work_thread_state_ret_.sleep_ns = 0;

        switch (work_thread_state_)
        {
        case WorkThreadStates::kInit:
            WorkThreadInitState();
            break;
        case WorkThreadStates::kDeinit:
            WorkThreadDeinitState();
            break;
        case WorkThreadStates::kFail:
            WorkThreadFailState();
            break;
        case WorkThreadStates::kWorking:
            WorkThreadWorkingState();
            break;
        default:
            work_thread_state_ret_.new_state = WorkThreadStates::kFail;
            work_thread_state_ret_.sleep_ns = 0;
            break;
        }

        if (work_thread_state_ret_.sleep_ns > 0)
        {
            std::unique_lock<std::mutex> lock(work_thread_wait_mutex_);
            work_thread_wait_cond_.wait_for(lock, std::chrono::nanoseconds(work_thread_state_ret_.sleep_ns), [this] {return (!work_thread_running_); });
        }

        if (work_thread_state_ret_.new_state != work_thread_state_)
        {
            work_thread_state_ = work_thread_state_ret_.new_state;
        }
    }

    // 清理
    WorkThreadDeinitState();
}

void Dumper::WorkThreadInitState()
{
    std::vector<char> pcap_errbuf(PCAP_ERRBUF_SIZE);

    /* open the adapter */
    pcap_ = pcap_create(param_->interface_device.c_str(), &pcap_errbuf[0]);
    if (!pcap_)
    {
        LIB_LOG(LogLevels::kError, "Couldn't create pcap {}: {}",
            param_->interface_device, &pcap_errbuf[0]);
        work_thread_state_ret_.new_state = WorkThreadStates::kFail;
        return;
    }

    if (0 != pcap_set_snaplen(pcap_, 65535))
    {
        LIB_LOG(LogLevels::kError, "Couldn't set pcap snaplen={}: {}",
            65535, pcap_geterr(pcap_));
        work_thread_state_ret_.new_state = WorkThreadStates::kFail;
        return;
    }

    if (0 != pcap_set_promisc(pcap_, (param_->promisc) ? 1 : 0))
    {
        LIB_LOG(LogLevels::kError, "Couldn't set pcap promisc={}: {}",
            param_->promisc, pcap_geterr(pcap_));
        work_thread_state_ret_.new_state = WorkThreadStates::kFail;
        return;
    }

    if (0 != pcap_set_tstamp_precision(pcap_, PCAP_TSTAMP_PRECISION_NANO))
    {
        LIB_LOG(LogLevels::kWarn, "Couldn't set pcap timestamp precision={}: {}",
            "PCAP_TSTAMP_PRECISION_NANO", pcap_geterr(pcap_));
    }

    if (0 != pcap_activate(pcap_))
    {
        LIB_LOG(LogLevels::kError, "Couldn't active pcap handle, {}", pcap_geterr(pcap_));
        work_thread_state_ret_.new_state = WorkThreadStates::kFail;
        return;
    }

    pcap_link_type_ = pcap_datalink(pcap_);
    if ((DLT_NULL != pcap_link_type_) && (DLT_EN10MB != pcap_link_type_))
    {
        LIB_LOG(LogLevels::kError, "Device doesn't provide Ethernet headers - link type was {}", pcap_link_type_);
        work_thread_state_ret_.new_state = WorkThreadStates::kFail;
        return;
    }

    /* compile the filter */
    memset(&pcap_bfp_, 0, sizeof(pcap_bfp_));
    std::string filter_str = GetFilter();
    bpf_u_int32 netmask = 0;
    if (PCAP_ERROR == pcap_compile(pcap_, &pcap_bfp_, filter_str.c_str(), 0, netmask))
    {
        LIB_LOG(LogLevels::kError, "Couldn't parse filter {}: {}", filter_str, pcap_geterr(pcap_));
        work_thread_state_ret_.new_state = WorkThreadStates::kFail;
        return;
    }

    /* set the filter */
    if (PCAP_ERROR == pcap_setfilter(pcap_, &pcap_bfp_))
    {
        LIB_LOG(LogLevels::kError, "Couldn't install filter {}: {}", filter_str, pcap_geterr(pcap_));
        work_thread_state_ret_.new_state = WorkThreadStates::kFail;
        return;
    }

    /* set nonblock */
    if (PCAP_ERROR == pcap_setnonblock(pcap_, 1, &pcap_errbuf[0]))
    {
        LIB_LOG(LogLevels::kError, "Couldn't set nonblock mode {}: {}", filter_str, &pcap_errbuf[0]);
        work_thread_state_ret_.new_state = WorkThreadStates::kFail;
        return;
    }

    pcap_tstamp_precision_ = (PCAP_TSTAMP_PRECISION_NANO == pcap_get_tstamp_precision(pcap_)) ? 1 : 1000;

    LIB_LOG(LogLevels::kInfo, "Init pcap device={} addr={}:{} filter={} successfully",
        param_->interface_device, param_->ip, param_->port, filter_str);
    work_thread_state_ret_.new_state = WorkThreadStates::kWorking;
}

void Dumper::WorkThreadDeinitState()
{
    if (pcap_dumper_)
    {
        pcap_dump_close(pcap_dumper_);
        pcap_dumper_ = nullptr;
    }

    if (pcap_)
    {
        pcap_close(pcap_);
        pcap_ = nullptr;
    }

    work_thread_state_ret_.new_state = WorkThreadStates::kInit;
    work_thread_state_ret_.sleep_ns = 1000000LL;
}

void Dumper::WorkThreadFailState()
{
    WorkThreadDeinitState();
    work_thread_state_ret_.sleep_ns = 3 * 1000000000LL;
}

void Dumper::WorkThreadWorkingState()
{
    const u_char *packet = nullptr;
    struct pcap_pkthdr *pcap_header = nullptr;

    /* grab a packet */
    int ret = pcap_next_ex(pcap_, &pcap_header, &packet);
    if (ret < 0)
    {
        LIB_LOG(LogLevels::kError, "Get pcap error: {}", pcap_geterr(pcap_));
        work_thread_state_ret_.new_state = WorkThreadStates::kFail;
        return;
    }

    if (0 == ret)
    {
        work_thread_state_ret_.sleep_ns = 1000000LL;
        return;
    }

    time_t pcap_header_time = pcap_header->ts.tv_sec;
    if (!(pcap_dumper_) ||
        (pcap_header_time / param_->segment_interval != pcap_dumper_prev_time_ / param_->segment_interval))
    {
        std::tm time_tm;
#if defined(_MSC_VER)
        ::localtime_s(&time_tm, &pcap_header_time);
#else
        ::localtime_r(&pcap_header_time, &time_tm);
#endif

        std::string file_name = lccl::OsPathJoin(file_dir_name_,
            fmt::format("{}_{:04}{:02}{:02}_{:02}{:02}{:02}.pcap",
                file_name_idx_,
                time_tm.tm_year + 1900,
                time_tm.tm_mon + 1,
                time_tm.tm_mday,
                time_tm.tm_hour,
                time_tm.tm_min,
                time_tm.tm_sec));
        ++file_name_idx_;

        if (pcap_dumper_)
        {
            pcap_dump_close(pcap_dumper_);
        }

        pcap_dumper_ = pcap_dump_open(pcap_, file_name.c_str());
        if (!pcap_dumper_)
        {
            LIB_LOG(LogLevels::kError, "Pcap dumper open error: {}", pcap_geterr(pcap_));
            work_thread_state_ret_.new_state = WorkThreadStates::kFail;
            return;
        }

        file_names_.push_back(file_name);
        if (file_names_.size() > param_->segment_size)
        {
            const std::string &del_file_name = file_names_.front();
            LIB_LOG(LogLevels::kInfo, "New pcap file={}, del file={}",
                file_name, del_file_name);

            lccl::file::RemoveFile(del_file_name.c_str());
            file_names_.pop_front();
        }
        else
        {
            LIB_LOG(LogLevels::kInfo, "New pcap file={}", file_name);
        }

        pcap_dumper_prev_time_ = pcap_header_time;
    }

    pcap_dump(reinterpret_cast<u_char *>(pcap_dumper_), pcap_header, packet);
}

std::string Dumper::GetFilter() const
{
    std::string filter_str;
    if ("any" != param_->ip)
    {
        if (filter_str.length() > 0)
        {
            filter_str += fmt::format(" and dst host {}", param_->ip);
        }
        else
        {
            filter_str += fmt::format("dst host {}", param_->ip);
        }
    }

    if ("any" != param_->port)
    {
        if (filter_str.length() > 0)
        {
            filter_str += fmt::format(" and dst port {}", param_->port);
        }
        else
        {
            filter_str += fmt::format("dst port {}", param_->port);
        }
    }

    return filter_str;
}

std::shared_ptr<IDumper> CreateDumper()
{
    return std::make_shared<Dumper>();
}

PCAP_DUMP_END_NAMESPACE
