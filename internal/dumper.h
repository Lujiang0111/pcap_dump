#ifndef PCAP_DUMP_INTERNAL_DUMPER_H_
#define PCAP_DUMP_INTERNAL_DUMPER_H_

#include <condition_variable>
#include <deque>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include "pcap.h"
#include "pcap_dump.h"

PCAP_DUMP_BEGIN_NAMESPACE

class Dumper : public IDumper
{
public:
    struct Param
    {
        std::string ip;
        std::string port;
        std::string interface_name;
        std::string interface_device;
        bool promisc = false;
        int64_t segment_interval = 30;
        size_t segment_size = 10;
        std::string dump_dir;
    };

public:
    Dumper(const Dumper &) = delete;
    Dumper &operator=(const Dumper &) = delete;

    Dumper();
    virtual ~Dumper();

    virtual bool SetParam(ParamNames param_name, const void *val, size_t size);

    virtual bool Init();
    virtual void Deinit();

private:
    enum class WorkThreadStates
    {
        kInit = 0,
        kDeinit,
        kFail,
        kWorking,
    };

    struct WorkThreadStateRet
    {
        WorkThreadStates new_state = WorkThreadStates::kFail;
        int64_t sleep_ns = 0;
    };

private:
    bool ParseParam();

    void WorkThread();
    void WorkThreadInitState();
    void WorkThreadDeinitState();
    void WorkThreadFailState();
    void WorkThreadWorkingState();

    std::string GetFilter() const;

private:
    std::vector<std::shared_ptr<std::vector<uint8_t>>> in_params_;
    std::shared_ptr<Param> param_;

    // 线程
    std::thread work_thread_;
    bool work_thread_running_;
    WorkThreadStates work_thread_state_;
    WorkThreadStateRet work_thread_state_ret_;
    std::mutex work_thread_wait_mutex_;
    std::condition_variable work_thread_wait_cond_;

    // pcap
    pcap_t *pcap_;
    int pcap_link_type_;
    bpf_program pcap_bfp_;
    int64_t pcap_tstamp_precision_;

    // pcap dump
    pcap_dumper_t *pcap_dumper_;
    int64_t pcap_dumper_prev_time_;

    // dump files
    std::string file_dir_name_;
    std::deque<std::string> file_names_;
    int file_name_idx_;
};

PCAP_DUMP_END_NAMESPACE

#endif // !PCAP_DUMP_INTERNAL_DUMPER_H_
