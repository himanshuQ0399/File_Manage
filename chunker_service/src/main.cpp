#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "chunker.h"
#include "server.h"
#include <httplib.h>
#include <windows.h>
#include <iostream>
#include <filesystem>

#define SERVICE_NAME L"ChunkerService"

SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE ServiceStatusHandle;
Chunker* global_chunker = nullptr;
httplib::SSLServer* global_svr = nullptr;

void LogEvent(const std::wstring& message, WORD eventType = EVENTLOG_INFORMATION_TYPE) {
    HANDLE eventLog = RegisterEventSourceW(nullptr, SERVICE_NAME);
    if (eventLog) {
        LPCWSTR strings[] = { message.c_str(), nullptr };
        ReportEventW(eventLog, eventType, 0, 0, nullptr, 1, 0, strings, nullptr);
        DeregisterEventSource(eventLog);
    }
}

void WINAPI ServiceControlHandler(DWORD control) {
    LogEvent(L"ServiceControlHandler received control: " + std::to_wstring(control));
    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
        if (global_svr) {
            global_svr->stop();
            delete global_svr;
            global_svr = nullptr;
        }
        if (global_chunker) {
            delete global_chunker;
            global_chunker = nullptr;
        }
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
        break;
    default:
        SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
        break;
    }
}

void WINAPI ServiceMain(DWORD argc, LPWSTR* argv) {
    LogEvent(L"ServiceMain started");
    ServiceStatusHandle = RegisterServiceCtrlHandlerW(SERVICE_NAME, ServiceControlHandler);
    if (!ServiceStatusHandle) {
        LogEvent(L"RegisterServiceCtrlHandlerW failed: " + std::to_wstring(GetLastError()), EVENTLOG_ERROR_TYPE);
        return;
    }

    ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode = 0;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint = 0;
    ServiceStatus.dwWaitHint = 10000;
    SetServiceStatus(ServiceStatusHandle, &ServiceStatus);

    try {
        global_chunker = new Chunker("https://localhost:8081");
        global_svr = new httplib::SSLServer("C:\\Users\\Qikfox\\Documents\\file_parallelism\\server.crt",
                                            "C:\\Users\\Qikfox\\Documents\\file_parallelism\\server.key");
        setup_server(*global_chunker, *global_svr);
        ServiceStatus.dwCurrentState = SERVICE_RUNNING;
        SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
        if (!global_svr->listen("0.0.0.0", 8080)) {
            LogEvent(L"Failed to start HTTPS server", EVENTLOG_ERROR_TYPE);
            ServiceStatus.dwCurrentState = SERVICE_STOPPED;
            ServiceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
            ServiceStatus.dwServiceSpecificExitCode = 1;
            SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
            return;
        }
    } catch (const std::exception& e) {
        LogEvent(L"ServiceMain exception: " + std::wstring(e.what(), e.what() + strlen(e.what())), EVENTLOG_ERROR_TYPE);
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        ServiceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
        ServiceStatus.dwServiceSpecificExitCode = 2;
        SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
    }
}

int main(int argc, char* argv[]) {
    std::cerr << "[Main] Working directory: " << std::filesystem::current_path() << "\n";
    if (argc > 1 && std::string(argv[1]) == "--console") {
        LogEvent(L"Running in console mode");
        Chunker chunker("https://localhost:8081");
        httplib::SSLServer svr("C:\\Users\\Qikfox\\Documents\\file_parallelism\\server.crt",
                               "C:\\Users\\Qikfox\\Documents\\file_parallelism\\server.key");
        setup_server(chunker, svr);
        if (!svr.listen("0.0.0.0", 8080)) {
            LogEvent(L"Failed to start HTTPS server", EVENTLOG_ERROR_TYPE);
            return 1;
        }
    } else {
        SERVICE_TABLE_ENTRYW ServiceTable[] = {
            { (LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTIONW)ServiceMain },
            { nullptr, nullptr }
        };
        LogEvent(L"Starting Service Control Dispatcher");
        if (!StartServiceCtrlDispatcherW(ServiceTable)) {
            LogEvent(L"StartServiceCtrlDispatcherW failed: " + std::to_wstring(GetLastError()), EVENTLOG_ERROR_TYPE);
            return 1;
        }
    }
    return 0;
}