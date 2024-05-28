// LoadDriverByDll.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <psapi.h>

using namespace std;

extern "C" typedef BOOL(__cdecl* LoadDriver)(char* lpszDriverName, char* lpszDriverPath);
extern "C" typedef BOOL(__cdecl* UnloadDriver)(char* szSvrName);
extern "C" typedef BOOL(__cdecl* DeviceControl)(_In_ char* lpszDriverName, _In_ LPWSTR ProtectProcessName, _In_ ULONG_PTR ProtectProcessPid);
extern "C" typedef int(__cdecl* GetProcessState)(DWORD dwProcessID);





HANDLE hToken;
LUID DebugNameValue;
TOKEN_PRIVILEGES Privileges;



//挂起进程，调用未公开函数NtSuspendProcess。suspend参数决定挂起/恢复 测试使用  
typedef NTSTATUS(WINAPI* NtSuspendProcess)(IN HANDLE Process);
typedef NTSTATUS(WINAPI* NtResumeProcess)(IN HANDLE Process);
BOOL SuspendProcess(DWORD dwProcessID, BOOL suspend) {
	NtSuspendProcess mNtSuspendProcess;
	NtResumeProcess mNtResumeProcess;
	HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
	HANDLE handle = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, dwProcessID);
	if (suspend) {
		mNtSuspendProcess = (NtSuspendProcess)GetProcAddress(ntdll, "NtSuspendProcess");
		return mNtSuspendProcess(handle) == 0;
	}
	else {
		mNtResumeProcess = (NtResumeProcess)GetProcAddress(ntdll, "NtResumeProcess");
		return mNtResumeProcess(handle) == 0;
	}
}


/*
提升进程权限
*/
bool improvePv()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) return false;
	if (!LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid)) return false;
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, NULL, NULL, NULL)) return false;
	return true;
}
/*
注销
*/
bool logOffProc()
{
	if (!improvePv() || !ExitWindowsEx(EWX_LOGOFF | EWX_FORCE, SHTDN_REASON_MAJOR_APPLICATION)) return false;
	return true;
}
/*
重启
*/
bool reBootProc()
{
	if (!improvePv() || !ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_APPLICATION)) return false;
	return true;
}

//隐藏cmd窗口
void HideWindow()
{
	HWND hwnd = GetForegroundWindow();
	if (hwnd)

	{
		ShowWindow(hwnd, SW_HIDE);
	}
}


//通过名字获取进程pid，并且检测其PE指纹是否为先前标识
//返回FALSE可能以下原因：进程更新重启中、进程非正常退出(这个情况不管，继续轮询检测进程是否被idle)

INT CheckTargetProcessID_PE(IN PCWSTR ProtectProcessName = L"RTCDesktop.exe")
{
	// 获取系统中的所有进程快照
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	HANDLE targetProcessHandle;
	INT result = 0;
	int error_code = 0;

	HMODULE hModule[100] = { 0 };
	BYTE p[1000] = {0};
	//INT P_SIZE = sizeof(p);
	DWORD dwRet = 0;
	DWORD dwNumberOfBytesRead;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		std::cerr << "Error: CreateToolhelp32Snapshot failed." << std::endl;
		return 0;
	}

	// 设置结构体大小
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// 遍历进程列表
	if (Process32First(hProcessSnap, &pe32)) 
	{
		do 
		{
			// 进程名称
 			std::wstring processName(pe32.szExeFile);

			// 在这里检查进程名称是否匹配你要查找的名称
			if (processName == ProtectProcessName)
			{
				std::wcout << L"Process found: " << processName << std::endl;
				
				targetProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
				if (targetProcessHandle != NULL && targetProcessHandle != INVALID_HANDLE_VALUE)
				{
					EnumProcessModulesEx(targetProcessHandle, hModule, sizeof(hModule), &dwRet, LIST_MODULES_64BIT);
				
					ReadProcessMemory(targetProcessHandle, *(hModule), &p, sizeof(hModule), (SIZE_T*)&dwNumberOfBytesRead);

				if(dwNumberOfBytesRead)
				{
					if (*(p+0x15) == 0xff)
					{
						result =  pe32.th32ProcessID;
						CloseHandle(targetProcessHandle);
						CloseHandle(hProcessSnap);
						return result;
					}
					else if (!p[0])
					{
						printf("hModule 获取失败:\n");
						continue;

					}
					else
					{
						CloseHandle(targetProcessHandle);
						CloseHandle(hProcessSnap);
						result = 4;//说明有伪装的RTCDesktop
						return result;
					}
				}
				else
				{
					error_code = GetLastError();
					printf("QueryFullProcessImageName 获取full_path失败，,错误码:%d\n",error_code);
					CloseHandle(targetProcessHandle);
					
				}
				}
			}
		} while (Process32Next(hProcessSnap, &pe32));
	}

	CloseHandle(hProcessSnap);

	return result;
}



int main(int argc, char* argv[])
{

	//创建一个互斥体，带有GUID的，如果成功，则返回有效句柄值 生成GUID
	HANDLE mutexHandle = CreateMutexW(NULL, FALSE, L"Global\\{{E96AE1E5-D4CC-48C5-BD86-A2844E8A6A8D}}");
	if (ERROR_ALREADY_EXISTS == GetLastError())
	{
		if (mutexHandle) {
			CloseHandle(mutexHandle);
		}
		printf("正在运行，不要再开启新实例.\n");
		return 0;
	}
	std::cout << "starting" << std::endl;




	int return_num = 0;
	
	//SuspendProcess(3308, 1);
	HideWindow();
	
	HMODULE _hDllInst = LoadLibraryW(L"LoadDriverByPs.dll");
	//获取进程的状态
	//返回-1，表示发生异常
	//返回0，表示进程没有被挂起
	//返回1，表示进程处于挂起状态
	GetProcessState GET_PROCESS_STATE = (GetProcessState)GetProcAddress(_hDllInst, "GetProcessState");

	if (GET_PROCESS_STATE == 0)return 0;

	for (;;)
	{

		/*
		int pid = 8292;
		printf(argv[1]);
		int PID = atoi(argv[1]);
		printf("\nPID:,%d\n", PID);*/

		INT PID = CheckTargetProcessID_PE();

		return_num = GET_PROCESS_STATE(PID);

		printf("return_num:,%d\n", return_num);

		
		if (return_num || PID == 4)
		{
			reBootProc();
		}
		

		Sleep(60000);
		
	}

	FreeLibrary(_hDllInst);


}


