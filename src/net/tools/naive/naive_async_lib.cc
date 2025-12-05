#include "net/tools/naive/naive_async_lib.h"

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

namespace {

// Global state to keep the network thread alive
std::thread* g_network_thread = nullptr;
base::SingleThreadTaskExecutor* g_io_executor = nullptr;
net::URLRequestContext* g_context = nullptr;
std::unique_ptr<net::URLRequestContext> g_context_owner;
int g_next_id = 1;

// The internal Delegate that receives events from Chromium
class SimpleClient : public net::URLRequest::Delegate {
public:
    SimpleClient(int id, NaiveCallbacks cb) : id_(id), cb_(cb) {
        // modern Chromium requires explicit sizing for IO buffers
        buffer_ = base::MakeRefCounted<net::IOBufferWithSize>(4096);
    }

    void OnResponseStarted(net::URLRequest* request, int net_error) override {
        if (net_error != net::OK) {
            cb_.on_connect(id_, net_error);
            delete this;
            return;
        }

        // Notify connection success
        cb_.on_connect(id_, 0);

        // Start reading immediately
        int bytes_read = request->Read(buffer_.get(), 4096);

        if (bytes_read > 0) {
            // Data available synchronously
            OnReadCompleted(request, bytes_read);
        } else if (bytes_read != net::ERR_IO_PENDING) {
            // Immediate error/EOF
            cb_.on_close(id_);
            delete this;
        }
    }

    void OnReadCompleted(net::URLRequest* request, int bytes_read) override {
        if (bytes_read > 0) {
            // Send data to the external app
            cb_.on_read(id_, buffer_->data(), bytes_read);

            // Queue next read
            int result = request->Read(buffer_.get(), 4096);
            if (result > 0) {
                OnReadCompleted(request, result);
            } else if (result != net::ERR_IO_PENDING) {
                cb_.on_close(id_);
                delete this;
            }
        } else {
            // EOF or Error
            cb_.on_close(id_);
            delete this;
        }
    }

private:
    int id_;
    NaiveCallbacks cb_;
    scoped_refptr<net::IOBufferWithSize> buffer_;

public:
    // Keep request alive as long as client exists
    std::unique_ptr<net::URLRequest> request_;
};

} // namespace

// The dedicated background thread function
void InitNetworkThread() {
    // 1. Initialize core Chromium environment
    static base::AtExitManager exit_manager;
    base::CommandLine::Init(0, nullptr);

    // 2. Configure logging
    logging::LoggingSettings settings;
    settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG | logging::LOG_TO_STDERR;
    logging::InitLogging(settings);

    // 3. Start Thread Pool
    base::ThreadPoolInstance::CreateAndStartWithDefaultParams("NaivePool");

    // 4. Create IO Task Runner (The heart of the network stack)
    g_io_executor = new base::SingleThreadTaskExecutor(base::MessagePumpType::IO);

    // 5. Build the URL Context (Cookie jar, cache, etc.)
    auto builder = std::make_unique<net::URLRequestContextBuilder>();
    // Disable cache for this simple example
    builder->DisableHttpCache();
    g_context_owner = builder->Build();
    g_context = g_context_owner.get();

    // 6. Block this thread forever running tasks
    base::RunLoop().Run();
}

// --- C API Implementation ---

extern "C" {

void Naive_Init() {
    if (!g_network_thread) {
        g_network_thread = new std::thread(InitNetworkThread);
        // Wait briefly for init (Primitive synchronization)
        // In production, use a std::promise/future here
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

void Naive_Connect(const char* url, NaiveCallbacks cb) {
    if (!g_io_executor) return;

    std::string url_str(url);

    // Post the work to the Chromium IO thread
    g_io_executor->task_runner()->PostTask(FROM_HERE, base::BindOnce([](std::string u, NaiveCallbacks c) {
        int id = g_next_id++;
        SimpleClient* client = new SimpleClient(id, c);

        // Create the request
        std::unique_ptr<net::URLRequest> req = g_context->CreateRequest(
            GURL(u), net::DEFAULT_PRIORITY, client, TRAFFIC_ANNOTATION_FOR_TESTS);

        req->Start();

        // Transfer ownership of request to the client so it stays alive
        client->request_ = std::move(req);

    }, url_str, cb));
}

} // extern "C"
