#include <memory>
#include <thread>
#include <map>
#include <mutex>

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

#if defined(WIN32)
#define NAIVE_EXPORT __declspec(dllexport)
#else
#define NAIVE_EXPORT __attribute__((visibility("default")))
#endif

// --- TYPES ---

typedef int ConnectionID;

// Callbacks provided by the Rust/ASIO side
typedef void (*OnConnectFunc)(ConnectionID id, int error);
typedef void (*OnReadFunc)(ConnectionID id, const char* data, int len);
typedef void (*OnCloseFunc)(ConnectionID id);

struct Callbacks {
    OnConnectFunc on_connect;
    OnReadFunc on_read;
    OnCloseFunc on_close;
};

// --- INTERNAL STATE ---

namespace {

std::thread* g_network_thread = nullptr;
base::SingleThreadTaskExecutor* g_io_executor = nullptr;
net::URLRequestContext* g_context = nullptr;
std::unique_ptr<net::URLRequestContext> g_context_owner;

// Map ID -> Request
int g_next_id = 1;
// Note: In a real app, protect this map with a lock if accessing from multiple threads,
// though typically we only touch it on the Network Thread.
// For simplicity here, we will dispatch everything to the Network Thread.

class SimpleClient : public net::URLRequest::Delegate {
public:
    SimpleClient(ConnectionID id, Callbacks cb) : id_(id), cb_(cb) {}

    void OnResponseStarted(net::URLRequest* request, int net_error) override {
        if (net_error != net::OK) {
            cb_.on_connect(id_, net_error);
            return;
        }
        cb_.on_connect(id_, 0); // Success

        // Start Reading
        int bytes_read = 0;
        request->Read(buffer_.get(), 4096, &bytes_read);
    }

    void OnReadCompleted(net::URLRequest* request, int bytes_read) override {
        if (bytes_read > 0) {
            cb_.on_read(id_, buffer_->data(), bytes_read);
            // Read loop
            int next_bytes = 0;
            request->Read(buffer_.get(), 4096, &next_bytes);
        } else {
            cb_.on_close(id_);
            delete this; // Commit sudoku
        }
    }

    scoped_refptr<net::IOBuffer> buffer_ = base::MakeRefCounted<net::IOBuffer>(4096);
    ConnectionID id_;
    Callbacks cb_;
};

} // namespace

// --- HELPER RUNNER ---

void InitNetworkThread() {
    static base::AtExitManager exit_manager;
    base::CommandLine::Init(0, nullptr);

    // Logging
    logging::LoggingSettings settings;
    settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
    logging::InitLogging(settings);

    base::ThreadPoolInstance::CreateAndStartWithDefaultParams("NaivePool");

    g_io_executor = new base::SingleThreadTaskExecutor(base::MessagePumpType::IO);

    // Build Context
    auto builder = net::CreateURLRequestContextBuilder();
    g_context_owner = builder->Build();
    g_context = g_context_owner.get();

    // Run forever
    base::RunLoop().Run();
}

// --- EXPORTED API ---

extern "C" {

NAIVE_EXPORT void Naive_Init() {
    if (!g_network_thread) {
        g_network_thread = new std::thread(InitNetworkThread);
        // Wait for init? In production you should use a condition variable here.
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

NAIVE_EXPORT void Naive_Connect(const char* url, Callbacks cb) {
    if (!g_io_executor) return;

    std::string url_str(url);

    // Post task to Chromium Thread
    g_io_executor->task_runner()->PostTask(FROM_HERE, base::BindOnce([](std::string u, Callbacks c) {
        ConnectionID id = g_next_id++;

        // This leaks if not cleaned up, SimpleClient manages its own lifetime in this demo
        SimpleClient* client = new SimpleClient(id, c);

        std::unique_ptr<net::URLRequest> req = g_context->CreateRequest(
            GURL(u), net::DEFAULT_PRIORITY, client);

        req->Start();

        // In a real implementation, store 'req' in a map<ConnectionID, unique_ptr<URLRequest>>
        // so you can cancel/write to it later.
        client->request_ = std::move(req);

    }, url_str, cb));
}

} // extern "C"
