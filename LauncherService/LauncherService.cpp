#include <windows.h>
#include <winsvc.h>
#include <Tlhelp32.h>
#include <process.h>
#include <psapi.h>
#include <sddl.h>

#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <thread>

#include "include/spdlog/sinks/basic_file_sink.h"
#include "include/spdlog/spdlog.h"

static WCHAR kServiceName[] = L"StudioYS Launcher Service";

SERVICE_STATUS_HANDLE service_state_handle;
BOOL is_running = FALSE;

std::mutex mutex_lock;

SC_HANDLE OpenSCM(DWORD desired_access)
{
	SC_HANDLE service_manager = OpenSCManagerW(NULL, NULL, desired_access);

	if ( service_manager == NULL )
	{
		spdlog::error("OpenSCManager Failed: 0x{:08x}", GetLastError());
	}

	return service_manager;
}

BOOL GetExplorerToken(HANDLE& hToken)
{
	spdlog::info("[GetExplorerToken] Start");

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if ( hSnapshot == INVALID_HANDLE_VALUE )
	{
		spdlog::error("[GetExplorerToken] CreateToolhelp32Snapshot Failed : 0x{:08x}", GetLastError());
		return FALSE;
	}

	DWORD explorerPID = 0;
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);

	// Find explorer.exe process
	if ( Process32First(hSnapshot, &pe) )
	{
		do
		{
			if ( _wcsicmp(pe.szExeFile, L"explorer.exe") == 0 )
			{
				explorerPID = pe.th32ProcessID;
				spdlog::debug("[GetExplorerToken] Found Explorer PID : {}", explorerPID);
				break;
			}
		} while ( Process32Next(hSnapshot, &pe) );
	}

	CloseHandle(hSnapshot);

	if ( explorerPID == 0 )
	{
		spdlog::error("[GetExplorerToken] Explorer process not found.");
		return FALSE;
	}

	// Open process and get token
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, explorerPID);
	if ( hProcess == NULL )
	{
		spdlog::error("[GetExplorerToken] OpenProcess failed for Explorer PID: 0x{:08x}", GetLastError());
		return FALSE;
	}

	if ( !OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken) )
	{
		CloseHandle(hProcess);
		spdlog::error("[GetExplorerToken] OpenProcessToken failed: 0x{:08x}", GetLastError());
		return FALSE;
	}

	CloseHandle(hProcess);
	spdlog::info("[GetExplorerToken] Successfully retrieved explorer token.");
	return TRUE;
}

BOOL RunAsExplorer(LPCWSTR lpApplicationName)
{
	HANDLE hToken;
	if ( !GetExplorerToken(hToken) )
	{
		spdlog::error("[RunAsExplorer] Failed to get explorer token");
		return FALSE;
	}

	HANDLE hNewToken;
	if ( !DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hNewToken) )
	{
		CloseHandle(hToken);
		spdlog::error("[RunAsExplorer] Failed to duplicate token: 0x{:08x}", GetLastError());
		return FALSE;
	}

	STARTUPINFOW si = { sizeof(STARTUPINFOW) };
	PROCESS_INFORMATION pi = { 0 };

	BOOL result = CreateProcessAsUserW(hNewToken, lpApplicationName, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

	if ( result )
	{
		spdlog::info("[RunAsExplorer] Successfully created process.");
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
	else
	{
		spdlog::error("[RunAsExplorer] Failed to create process: 0x{:08x}", GetLastError());
	}

	CloseHandle(hToken);
	CloseHandle(hNewToken);
	return result;
}

void WorkThread()
{
	spdlog::info("[WorkThread] Start");
	
	const std::wstring process_path = L"C:\\windows\\system32\\notepad.exe";

	BOOL executed = FALSE;
	

	while ( is_running )
	{
		if ( !executed )
		{
			if ( executed = RunAsExplorer(process_path.c_str()) )
			{
				spdlog::error("[WorkThread] run process");
			}
			else
			{
				spdlog::error("[WorkThread] Failed to run process");
			}
		}

		Sleep(2000);
	}

	spdlog::info("[WorkThread] Finish");
}

BOOL UpdateServiceStatus(DWORD current_state, DWORD exit_code, DWORD specific_exit_code, DWORD wait_hint)
{
	static DWORD check_point = 1;
	SERVICE_STATUS service_status = { 0 };
	service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	service_status.dwCurrentState = current_state;
	service_status.dwControlsAccepted = (current_state == SERVICE_RUNNING) ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN) : 0;
	service_status.dwWin32ExitCode = (specific_exit_code == 0) ? exit_code : ERROR_SERVICE_SPECIFIC_ERROR;
	service_status.dwServiceSpecificExitCode = specific_exit_code;
	service_status.dwWaitHint = wait_hint;
	service_status.dwCheckPoint = ((current_state == SERVICE_RUNNING) || (current_state == SERVICE_STOPPED)) ? 0 : check_point++;

	return SetServiceStatus(service_state_handle, &service_status);
}

DWORD WINAPI ServiceHandlerEx(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext)
{
	switch ( dwControl )
	{
	case SERVICE_CONTROL_SHUTDOWN:
	case SERVICE_CONTROL_STOP:
		spdlog::info("SERVICE_CONTROL_STOP received");
		UpdateServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 0, 0);
		is_running = FALSE;
		return NO_ERROR;
	default:
		break;
	}
	return NO_ERROR;
}

void ServiceMain(DWORD argc, LPCWSTR* argv)
{
	spdlog::info("[ServiceMain] Start");

	service_state_handle = RegisterServiceCtrlHandlerEx(kServiceName, ServiceHandlerEx, NULL);
	if ( service_state_handle == NULL )
	{
		spdlog::error("[ServiceMain] RegisterServiceCtrlHandlerEx failed: 0x{:08x}", GetLastError());
		return;
	}

	UpdateServiceStatus(SERVICE_START_PENDING, NO_ERROR, 0, 3000);

	is_running = TRUE;
	std::thread work_thread(WorkThread);

	UpdateServiceStatus(SERVICE_RUNNING, NO_ERROR, 0, 0);

	work_thread.join();
	UpdateServiceStatus(SERVICE_STOPPED, NO_ERROR, 0, 0);
}

void InstallMyService()
{
	SC_HANDLE service_manager = OpenSCM(SC_MANAGER_CREATE_SERVICE);
	if ( service_manager == NULL ) return;

	WCHAR file_path[MAX_PATH] = { 0 };
	GetModuleFileNameW(NULL, file_path, _countof(file_path));

	SC_HANDLE service_handle = CreateServiceW(
		service_manager, kServiceName, kServiceName, SERVICE_ALL_ACCESS,
		SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
		file_path, NULL, NULL, NULL, NULL, NULL);

	if ( service_handle == NULL )
	{
		spdlog::error("[InstallMyService] CreateService Failed: 0x{:08x}", GetLastError());
		CloseServiceHandle(service_manager);
		return;
	}

	WCHAR description[] = L"StudioYS Launcher Service Description";
	SERVICE_DESCRIPTION sd = { description };
	ChangeServiceConfig2W(service_handle, SERVICE_CONFIG_DESCRIPTION, &sd);

	CloseServiceHandle(service_handle);
	CloseServiceHandle(service_manager);

	spdlog::info("[InstallMyService] Service installed successfully.");
}

void UninstallMyService()
{
	SC_HANDLE service_manager = OpenSCM(SC_MANAGER_ALL_ACCESS);
	if ( service_manager == NULL ) return;

	SC_HANDLE service_handle = OpenService(service_manager, kServiceName, SERVICE_ALL_ACCESS);
	if ( service_handle == NULL )
	{
		spdlog::error("[UninstallMyService] OpenService Failed: 0x{:08x}", GetLastError());
		CloseServiceHandle(service_manager);
		return;
	}

	if ( !DeleteService(service_handle) )
	{
		spdlog::error("[UninstallMyService] DeleteService Failed: 0x{:08x}", GetLastError());
	}

	CloseServiceHandle(service_handle);
	CloseServiceHandle(service_manager);

	spdlog::info("[UninstallMyService] Service uninstalled successfully.");
}

void StartMyService()
{
	SC_HANDLE service_manager = OpenSCM(SC_MANAGER_ALL_ACCESS);
	if ( service_manager == NULL ) return;

	SC_HANDLE service_handle = OpenService(service_manager, kServiceName, SERVICE_ALL_ACCESS);
	if ( service_handle == NULL )
	{
		spdlog::error("[StartMyService] OpenService Failed: 0x{:08x}", GetLastError());
		CloseServiceHandle(service_manager);
		return;
	}

	if ( !StartService(service_handle, 0, NULL) )
	{
		spdlog::error("[StartMyService] StartService Failed: 0x{:08x}", GetLastError());
		CloseServiceHandle(service_handle);
		CloseServiceHandle(service_manager);
		return;
	}

	SERVICE_STATUS service_status;
	QueryServiceStatus(service_handle, &service_status);

	while ( service_status.dwCurrentState != SERVICE_RUNNING )
	{
		Sleep(service_status.dwWaitHint);
		QueryServiceStatus(service_handle, &service_status);
	}

	CloseServiceHandle(service_handle);
	CloseServiceHandle(service_manager);
	spdlog::info("[StartMyService] Service started successfully.");
}

void StopMyService()
{
	SC_HANDLE service_manager = OpenSCM(SC_MANAGER_ALL_ACCESS);
	if ( service_manager == NULL ) return;

	SC_HANDLE service_handle = OpenService(service_manager, kServiceName, SERVICE_ALL_ACCESS);
	if ( service_handle == NULL )
	{
		spdlog::error("[StopMyService] OpenService Failed: 0x{:08x}", GetLastError());
		CloseServiceHandle(service_manager);
		return;
	}

	SERVICE_STATUS service_status;
	QueryServiceStatus(service_handle, &service_status);

	if ( service_status.dwCurrentState != SERVICE_STOPPED )
	{
		if ( !ControlService(service_handle, SERVICE_CONTROL_STOP, &service_status) )
		{
			spdlog::error("[StopMyService] ControlService Failed: 0x{:08x}", GetLastError());
			CloseServiceHandle(service_handle);
			CloseServiceHandle(service_manager);
			return;
		}

		Sleep(2000);
	}

	CloseServiceHandle(service_handle);
	CloseServiceHandle(service_manager);
	spdlog::info("[StopMyService] Service stopped successfully.");
}

int main(int argc, char* argv[])
{
	const std::string log_file_path = "E:\\Log.txt";
	auto logger = spdlog::basic_logger_mt("basic_logger", log_file_path);
	spdlog::set_level(spdlog::level::trace);
	spdlog::set_default_logger(logger);
	spdlog::flush_on(spdlog::level::trace);

	spdlog::info("Main Start");

	SERVICE_TABLE_ENTRYW service_table[] = {
		{kServiceName, (LPSERVICE_MAIN_FUNCTIONW)ServiceMain},
		{nullptr, nullptr}
	};

	if ( argc >= 2 )
	{
		if ( _stricmp(argv[1], "--install") == 0 )
		{
			InstallMyService();
		}
		else if ( _stricmp(argv[1], "--uninstall") == 0 )
		{
			UninstallMyService();
		}
		else if ( _stricmp(argv[1], "--start") == 0 )
		{
			StartMyService();
		}
		else if ( _stricmp(argv[1], "--stop") == 0 )
		{
			StopMyService();
		}
	}
	else
	{
		StartServiceCtrlDispatcherW(service_table);
	}

	spdlog::info("Main Finish");
	return 0;
}
