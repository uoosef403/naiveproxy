    #ifndef NAIVE_ASYNC_LIB_H_
    #define NAIVE_ASYNC_LIB_H_

    #if defined(WIN32)
    #if defined(NAIVE_IMPLEMENTATION)
        #define NAIVE_EXPORT __declspec(dllexport)
    #else
        #define NAIVE_EXPORT __declspec(dllimport)
    #endif
    #else
    #define NAIVE_EXPORT __attribute__((visibility("default")))
    #endif

    #ifdef __cplusplus
    extern "C" {
    #endif

    // --- Types ---

    // Function pointers that YOUR app implements to handle events
    typedef void (*OnConnectFunc)(int id, int error);
    typedef void (*OnReadFunc)(int id, const char* data, int len);
    typedef void (*OnCloseFunc)(int id);

    struct NaiveCallbacks {
        OnConnectFunc on_connect;
        OnReadFunc on_read;
        OnCloseFunc on_close;
    };

    // --- Functions ---

    // Initialize the background network thread. Call this once at startup.
    NAIVE_EXPORT void Naive_Init();

    // Start a new request. Returns immediately.
    // Events will follow on the provided callbacks.
    NAIVE_EXPORT void Naive_Connect(const char* url, NaiveCallbacks cb);

    #ifdef __cplusplus
    }
    #endif

    #endif // NAIVE_ASYNC_LIB_H_
