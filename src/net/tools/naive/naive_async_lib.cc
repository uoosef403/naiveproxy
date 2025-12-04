#include <memory>
#include <thread>
#include <string>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/message_loop/message_pump_type.h"
#include "base/task/single_thread_task_executor.h"
#include "base/task/thread_pool/thread_pool_instance.h"
#include "base/run_loop.h"
#include "base/memory/scoped_refptr.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"

#if defined(WIN32)
#define NAIVE_EXPORT __declspec(dllexport)
#else
#define NAIVE_EXPORT __attribute__((visibility("default")))
#endif

typedef int ConnectionID;
typedef void (*OnConnectFunc)(ConnectionID id, int error);
typedef void (*OnReadFunc)(ConnectionID id, const char* data, int len);
typedef void (*OnCloseFunc)(ConnectionID id);

struct Callbacks {
    OnConnectFunc on_connect;
    OnReadFunc on_read;
    OnCloseFunc on_close;
};

namespace {

std::thread* g_network_thread = nullptr;
base::SingleThreadTaskExecutor* g_io_executor = nullptr;
net::URLRequestContext* g_context = nullptr;
std::unique_ptr<net::URLRequestContext> g_context_owner;
int g_next_id = 1;

class SimpleClient : public net::URLRequest::Delegate {
public:
    SimpleClient(ConnectionID id, Callbacks cb) : id_(id), cb_(cb) {
        // Allocate IOBuffer with explicit size (required in modern Chrome)
        buffer_ = base::MakeRefCounted<net::IOBufferWithSize>(4096);
    }

    void OnResponseStarted(net::URLRequest* request, int net_error) override {
        if (net_error != net::OK) {
            cb_.on_connect(id_, net_error);
            return;
        }
        cb_.on_connect(id_, 0);

        // FIX: Read now returns int directly (bytes read or error)
        // It does NOT take a 3rd pointer argument.
        int bytes_read = request->Read(buffer_.get(), 4096);

        if (bytes_read > 0) {
            // Data was available synchronously
            OnReadCompleted(request, bytes_read);
        } else if (bytes_read != net::ERR_IO_PENDING) {
            // Immediate error
            cb_.on_close(id_);
            delete this;
        }
    }

    void OnReadCompleted(net::URLRequest* request, int bytes_read) override {
        if (bytes_read > 0) {
            cb_.on_read(id_, buffer_->data(), bytes_read);

            // Read next chunk
            int result = request->Read(buffer_.get(), 4096);
            if (result > 0) {
                OnReadCompleted(request, result);
            } else if (result != net::ERR_IO_PENDING) {
                cb_.on_close(id_);
                delete this;
            }
        } else {
            // 0 = EOF, <0 = Error
            cb_.on_close(id_);
            delete this;
        }
    }

    scoped_refptr<net::IOBufferWithSize> buffer_;
    ConnectionID id_;
    Callbacks cb_;
    std::unique_ptr<net::URLRequest> request_;
};

} // namespace

void InitNetworkThread() {
    static base::AtExitManager exit_manager;
    base::CommandLine::Init(0, nullptr);

    logging::LoggingSettings settings;
    settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
    logging::InitLogging(settings);

    base::ThreadPoolInstance::CreateAndStartWithDefaultParams("NaivePool");

    g_io_executor = new base::SingleThreadTaskExecutor(base::MessagePumpType::IO);

    // FIX: URLRequestContextBuilder is a class, instantiating directly
    auto builder = std::make_unique<net::URLRequestContextBuilder>();
    g_context_owner = builder->Build();
    g_context = g_context_owner.get();

    base::RunLoop().Run();
}

extern "C" {

NAIVE_EXPORT void Naive_Init() {
    if (!g_network_thread) {
        g_network_thread = new std::thread(InitNetworkThread);
        // In production, use a condition variable here to wait for init
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

NAIVE_EXPORT void Naive_Connect(const char* url, Callbacks cb) {
    if (!g_io_executor) return;

    std::string url_str(url);

    g_io_executor->task_runner()->PostTask(FROM_HERE, base::BindOnce([](std::string u, Callbacks c) {
        ConnectionID id = g_next_id++;
        SimpleClient* client = new SimpleClient(id, c);

        // FIX: Added TRAFFIC_ANNOTATION_FOR_TESTS (Required argument)
        std::unique_ptr<net::URLRequest> req = g_context->CreateRequest(
            GURL(u), net::DEFAULT_PRIORITY, client, TRAFFIC_ANNOTATION_FOR_TESTS);

        req->Start();
        client->request_ = std::move(req);

    }, url_str, cb));
}

} // extern "C"
