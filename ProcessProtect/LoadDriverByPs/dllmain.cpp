// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <string>
#include "dllexport.h"
#include <winioctl.h>
#include <tlhelp32.h>
#include <windows.h>
#include <winternl.h>


#define IOCTRL_BASE 0x800

#define MYIOCTRL_CODE(i) \
	CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTRL_BASE+i, METHOD_BUFFERED,FILE_ANY_ACCESS)

#define CTL_START MYIOCTRL_CODE(0)
#define CTL_REBOOT MYIOCTRL_CODE(1)
#define CTL_CHECK_PE MYIOCTRL_CODE(2)
#define CTL_BYE MYIOCTRL_CODE(3)
#define CTL_HEARTBEAT MYIOCTRL_CODE(4)


#pragma warning(disable : 4996)



// 保存进程信息的结构体，包含进程ID和字符串
typedef struct _SAVE_STRUCT
{
	unsigned int g_save_pid;
	WCHAR str[50];
}SAVE_STRUCT, * PSAVE_STRUCT;

SAVE_STRUCT g_save = { 0 };

HANDLE drvhandle = 0;
std::string _driver_name = "";






typedef NTSTATUS(WINAPI* NTQUERYSYSTEMINFORMATION)(
	_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID                    SystemInformation,
	_In_      ULONG                    SystemInformationLength,
	_Out_opt_ PULONG                   ReturnLength
	);

#define SystemProcessInformation    5

typedef struct _VM_COUNTERS {
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
} VM_COUNTERS;

typedef struct _MYSYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER Reserved[3];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG PageDirectoryBase;
	VM_COUNTERS VirtualMemoryCounters;
	SIZE_T PrivatePageCount;
	IO_COUNTERS IoCounters;
	//以上为原结构内容
	SYSTEM_THREAD_INFORMATION Threads[0];
} MYSYSTEM_PROCESS_INFORMATION, * PMYSYSTEM_PROCESS_INFORMATION;

//覆盖原定义
#define SYSTEM_PROCESS_INFORMATION MYSYSTEM_PROCESS_INFORMATION
#define PSYSTEM_PROCESS_INFORMATION PMYSYSTEM_PROCESS_INFORMATION


typedef enum _KWAIT_REASON {//线程处于等待状态的原因
	Executive = 0,
	FreePage, PageIn, PoolAllocation, DelayExecution,
	Suspended/*挂起*/, UserRequest, WrExecutive, WrFreePage, WrPageIn,
	WrPoolAllocation, WrDelayExecution, WrSuspended,
	WrUserRequest, WrEventPair, WrQueue, WrLpcReceive,
	WrLpcReply, WrVirtualMemory, WrPageOut, WrRendezvous,
	Spare2, Spare3, Spare4, Spare5, Spare6, WrKernel,
	MaximumWaitReason
} KWAIT_REASON;

/**
 * 获取进程的状态
 *
 * @param dwProcessID 进程id
 * @return 
 * 返回-1，表示发生异常
 * 返回0，表示进程没有被挂起
 * 返回1，表示进程处于挂起状态
 * 
 */
int GetProcessState(DWORD dwProcessID) {
	int nStatus = -1;
	//取函数地址
	NTQUERYSYSTEMINFORMATION l_NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)(GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation"));
	//先调用一次，获取所需缓冲区大小
	DWORD dwSize;
	l_NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessInformation, NULL, 0, &dwSize);
	//申请缓冲区
	HGLOBAL hBuffer = GlobalAlloc(LPTR, dwSize);
	if (hBuffer == NULL)
		return nStatus;
	PSYSTEM_PROCESS_INFORMATION pInfo = PSYSTEM_PROCESS_INFORMATION(hBuffer);
	//查询
	NTSTATUS lStatus = l_NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessInformation, pInfo, dwSize, 0);
	if (!NT_SUCCESS(lStatus)) {
		GlobalFree(hBuffer);
		printf("l_NtQuerySystemInformation 查询进程信息失败\n");
		return nStatus;
	}

	//遍历进程
	while (true) {
		//判断是否是目标进程
		if (((DWORD)(ULONG_PTR)pInfo->UniqueProcessId) == dwProcessID) {

			
				
			nStatus = 1;
			//遍历线程
			for (ULONG i = 0; i < pInfo->NumberOfThreads; i++) {
				//如果不是在挂起，就表明程序存活，可以返回（堵塞、无响应不算挂起）
				if (pInfo->Threads[i].WaitReason != Suspended) {
					nStatus = 0;
					break;
				}
			}
			break;
		}
		//遍历进程完成
		if (pInfo->NextEntryOffset == 0)
			break;
		//移动到下一个进程信息结构的地址
		pInfo = PSYSTEM_PROCESS_INFORMATION(PBYTE(pInfo) + pInfo->NextEntryOffset);
	}
	//释放缓冲区
	GlobalFree(hBuffer);
	return nStatus;
}

/**
 * 检测PE指纹是否符合
 *
 * @param filepath  文件路径
 * return 是否符合指纹的布尔值
 */

BOOLEAN CheckPE(IN WCHAR* filepath)
{
	PIMAGE_DOS_HEADER pDosHeader;
	HANDLE hFile = CreateFile(filepath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("CreateFile error\n");
		int error = GetLastError();
		return 0;
	}
	HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	PVOID pbFile = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (hFile == INVALID_HANDLE_VALUE || hMapping == NULL || pbFile == NULL)
	{
		printf("\n========THE FILE IS NOT EXCTING===========\n");
		if (hFile != INVALID_HANDLE_VALUE)
		{
			CloseHandle(hFile);
		}
		if (hMapping != NULL)
		{
			CloseHandle(hMapping);
		}
		if (pbFile != NULL)
		{
			UnmapViewOfFile(pbFile);
		}

	}
	pDosHeader = (PIMAGE_DOS_HEADER)pbFile;


	return *((PCHAR)pDosHeader + 0x15) == 0xff ? 1 : 0;
}




/**
 * 设备驱动程序发送控制代码通用接口函数
 *
 * @param lpszDriverName 驱动名称
 * @param control_code  设备控制请求的控制码
 * @return 设备控制请求返回的布尔值
 *
 */
EXTERN_C BOOL __cdecl DeviceControlCommonInterface(char* lpszDriverName,DWORD control_code)
{
	BOOL bResult = FALSE;                 // results flag
	DWORD junk = 0;                     // discard results

	std::string className = "\\\\.\\";
	className += lpszDriverName;

	printf("c_str:%s\n", className.c_str());
	drvhandle = CreateFileA(className.c_str(),
		GENERIC_WRITE | GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);


	INT32 error_code = GetLastError();

	if (INVALID_HANDLE_VALUE == drvhandle)
		printf("CreateFile失败!%08X\n", error_code);
	
	bResult = DeviceIoControl(drvhandle,                       // device to be queried
		control_code, // operation to perform
		&g_save, sizeof(SAVE_STRUCT),                       // no input buffer
		NULL, 0,            // output buffer
		&junk,                         // # bytes returned
		NULL);          // synchronous I/O
	printf("bResult:%b", bResult);

	return (bResult);
}





/**
 * 向设备驱动程序发送控制代码CTL_HEARTBEAT，CTL_HEARTBEAT就是心跳的方式判断RTCDesktop.exe是否存活的功能
 *
 * @param lpszDriverName 驱动名称
 * @param control_code  设备控制请求的控制码
 * @return 设备控制请求返回的布尔值
 *
 */
EXTERN_C BOOL __cdecl DeviceControlHeartbeat(char* lpszDriverName)
{
	BOOL bResult = FALSE;                 // results flag
	DWORD junk = 0;                     // discard results

	static bool done = false;

	if (!done) {
		std::string className = "\\\\.\\";
		className += lpszDriverName;

		printf("c_str:%s\n", className.c_str());
		drvhandle = CreateFileA(className.c_str(),
			GENERIC_WRITE | GENERIC_READ,
			0,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);


		INT32 error_code = GetLastError();

		if (INVALID_HANDLE_VALUE == drvhandle)
		{
			printf("CreateFile失败!%08X\n", error_code);
			return bResult;
		}
		done = true;
	}

		bResult = DeviceIoControl(drvhandle,                       // device to be queried
			CTL_HEARTBEAT, // operation to perform
			&g_save, sizeof(SAVE_STRUCT),                       // no input buffer
			NULL, 0,            // output buffer
			&junk,                         // # bytes returned
			NULL);          // synchronous I/O

		printf("bResult:%b", bResult);

		if (!bResult) {
			printf("Error sending heartbeat: %lu\n", GetLastError());
			return bResult;
		}
		printf("Heartbeat sent.\n");
		

	
	return bResult;
}





/**
 * 进程保护入口函数
 *
 * @param lpszDriverName 驱动名称
 * @return 向进程保护设备驱动程序发送控制指令后的返回值
 */

EXTERN_C BOOL __cdecl PsProtectBegin(char* lpszDriverName)
{
	
	BOOL bResult = FALSE;                 // results flag
	DWORD junk = 0;                     // discard results
	
	std::string className = "\\\\.\\";
	className += lpszDriverName;

	printf("c_str:%s\n", className.c_str());
	drvhandle = CreateFileA(className.c_str(),
		GENERIC_WRITE | GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);


	INT32 error_code = GetLastError();

	if (INVALID_HANDLE_VALUE == drvhandle)
		printf("CreateFile失败!%08X\n", error_code);

	bResult = DeviceIoControl(drvhandle,                       // device to be queried
		CTL_REBOOT, // operation to perform
		&g_save, sizeof(SAVE_STRUCT),                       // no input buffer
		NULL, 0,            // output buffer
		&junk,                         // # bytes returned
		NULL);          // synchronous I/O
	printf("bResult:%b",bResult);
	
	return (bResult);
}


/**
 * 加载NT框架式驱动
 *
 * @param lpszDriverName 驱动名称
 * @param lpszDriverPath 驱动路径
 * @return 加载NT框架式驱动的错误码
 */
EXTERN_C BOOL __cdecl LoadNTDriver(char* lpszDriverName, char* lpszDriverPath)
{
	char szDriverImagePath[256];
	//得到完整的驱动路径
	GetFullPathNameA(lpszDriverPath, 256, szDriverImagePath, NULL);
	printf("FullPathName:%s\n", szDriverImagePath);
	BOOL bRet = FALSE;

	SC_HANDLE hServiceMgr = NULL;//SCM管理器的句柄
	SC_HANDLE hServiceDDK = NULL;//NT驱动程序的服务句柄

	//打开服务控制管理器
	hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	int error_code = GetLastError();
	if (hServiceMgr == NULL)
	{
		//OpenSCManager失败
		printf("OpenSCManager() Faild %d ! \n", GetLastError());
		bRet = FALSE;
		goto BeforeLeave;
	}
	else
	{
		////OpenSCManager成功
		printf("OpenSCManager() ok ! \n");
	}

	//创建驱动所对应的服务
	hServiceDDK = CreateServiceA(hServiceMgr,
		lpszDriverName, //驱动程序的在注册表中的名字  
		lpszDriverName, // 注册表驱动程序的 DisplayName 值  
		SERVICE_ALL_ACCESS, // 加载驱动程序的访问权限  
		SERVICE_KERNEL_DRIVER,// 表示加载的服务是驱动程序  
		SERVICE_DEMAND_START, // 注册表驱动程序的 Start 值  
		SERVICE_ERROR_IGNORE, // 注册表驱动程序的 ErrorControl 值  
		szDriverImagePath, // 注册表驱动程序的 ImagePath 值  
		NULL,
		NULL,
		NULL,
		NULL,
		NULL);

	DWORD dwRtn;
	//判断服务是否失败
	if (hServiceDDK == NULL)
	{
		dwRtn = GetLastError();
		if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_EXISTS)
		{
			//由于其他原因创建服务失败
			printf("CrateService() Faild %d ! \n", dwRtn);
			bRet = FALSE;
			goto BeforeLeave;
		}
		else
		{
			//服务创建失败，是由于服务已经创立过
			printf("CrateService() Faild Service is ERROR_IO_PENDING or ERROR_SERVICE_EXISTS! \n");
		}

		// 驱动程序已经加载，只需要打开  
		hServiceDDK = OpenServiceA(hServiceMgr, lpszDriverName, SERVICE_ALL_ACCESS);
		if (hServiceDDK == NULL)
		{
			//如果打开服务也失败，则意味错误
			dwRtn = GetLastError();
			printf("OpenService() Faild %d ! \n", dwRtn);
			bRet = FALSE;
			goto BeforeLeave;
		}
		else
		{
			printf("OpenService() ok ! \n");
		}
	}
	else
	{
		printf("CrateService() ok ! \n");
	}

	//开启此项服务
	bRet = StartService(hServiceDDK, NULL, NULL);
	if (!bRet)
	{
		DWORD dwRtn = GetLastError();
		if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_ALREADY_RUNNING)
		{
			printf("StartService() Faild %d ! \n", dwRtn);
			bRet = FALSE;
			goto BeforeLeave;
		}
		else
		{
			if (dwRtn == ERROR_IO_PENDING)
			{
				//设备被挂住
				printf("StartService() Faild ERROR_IO_PENDING ! \n");
				bRet = FALSE;
				goto BeforeLeave;
			}
			else
			{
				//服务已经开启
				printf("StartService() Faild ERROR_SERVICE_ALREADY_RUNNING ! \n");
				bRet = TRUE;
				goto BeforeLeave;
			}
		}
	}
	bRet = TRUE;
	//离开前关闭句柄
BeforeLeave:
	if (hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if (hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}
	return bRet;
}



/**
 * 卸载驱动程序  
 *
 * @param szSvrName 要打开的设备服务的名称
 * @return 打开指定设备服务布尔值
 */

EXTERN_C BOOL __cdecl UnloadNTDriver(char* szSvrName)
{
	BOOL bRet = FALSE;
	SC_HANDLE hServiceMgr = NULL;//SCM管理器的句柄
	SC_HANDLE hServiceDDK = NULL;//NT驱动程序的服务句柄
	SERVICE_STATUS SvrSta;
	//打开SCM管理器
	hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hServiceMgr == NULL)
	{
		//带开SCM管理器失败
		printf("OpenSCManager() Faild %d ! \n", GetLastError());
		bRet = FALSE;
		goto BeforeLeave;
	}
	else
	{
		//带开SCM管理器失败成功
		printf("OpenSCManager() ok ! \n");
	}
	//打开驱动所对应的服务
	hServiceDDK = OpenServiceA(hServiceMgr, szSvrName, SERVICE_ALL_ACCESS);

	if (hServiceDDK == NULL)
	{
		//打开驱动所对应的服务失败
		printf("OpenService() Faild %d ! \n", GetLastError());
		bRet = FALSE;
		goto BeforeLeave;
	}
	else
	{
		printf("OpenService() ok ! \n");
	}
	//停止驱动程序，如果停止失败，只有重新启动才能，再动态加载。  
	if (!ControlService(hServiceDDK, SERVICE_CONTROL_STOP, &SvrSta))
	{
		printf("ControlService() Faild %d !\n", GetLastError());
	}
	else
	{
		//打开驱动所对应的失败
		printf("ControlService() ok !\n");
	}
	//动态卸载驱动程序。  
	if (!DeleteService(hServiceDDK))
	{
		//卸载失败
		printf("DeleteSrevice() Faild %d !\n", GetLastError());
	}
	else
	{
		//卸载成功
		printf("DelServer:eleteSrevice() ok !\n");
	}
	bRet = TRUE;
BeforeLeave:
	//离开前关闭打开的句柄
	if (hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if (hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}
	return bRet;
}


//对外开放的卸载接口
EXTERN_C BOOL __cdecl LoadDriver(char* lpszDriverName, char* lpszDriverPath)
{
	_driver_name = lpszDriverName;
	BOOL loadDriverRetVal = LoadNTDriver(lpszDriverName, lpszDriverPath);


	return loadDriverRetVal;
}



//对外开放的卸载接口
EXTERN_C BOOL __cdecl UnloadDriver(char* szSvrName)
{
	CloseHandle(drvhandle);
	return UnloadNTDriver((char*)_driver_name.c_str());
}


/**
 * 向保护设备驱动程序发送控制代码函数
 *
 * @param lpszDriverName 驱动名称
 * @param ProtectProcessName 要保护的进程名称
 * @param ProtectProcessPid 要保护的进程id
 * @return 发送设备驱动控制指令后的返回值
 */
EXTERN_C BOOL __cdecl DeviceControl(_In_ char* lpszDriverName, _In_  LPWSTR ProtectProcessName, _In_ ULONG_PTR ProtectProcessPid)
{
	BOOL bResult = FALSE;                 // results flag
	DWORD junk = 0;                     // discard results
	OVERLAPPED varOverLapped;
	HANDLE varObjectHandle = 0;

	varObjectHandle = CreateEvent(NULL, TRUE, TRUE, L"");
	if (varObjectHandle == NULL)return bResult;

	// ini OverLAppend
	memset(&varOverLapped, 0, sizeof(OVERLAPPED));
	varOverLapped.hEvent = varObjectHandle;
	varOverLapped.Offset = 0;
	varOverLapped.OffsetHigh = 0;



	std::string className = "\\\\.\\";
	className += lpszDriverName;

	printf("c_str:%s\n", className.c_str());
	drvhandle = CreateFileA(className.c_str(),
		GENERIC_WRITE | GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	wcscpy(g_save.str, ProtectProcessName);
	g_save.g_save_pid = ProtectProcessPid;

	INT32 error_code = GetLastError();

	if (INVALID_HANDLE_VALUE == drvhandle)
		printf("CreateFile失败!%08X\n", error_code);

	bResult = DeviceIoControl(drvhandle,                       // device to be queried
		CTL_START, // operation to perform
		&g_save, sizeof(SAVE_STRUCT),                       // no input buffer
		NULL, 0,            // output buffer
		&junk,                         // # bytes returned
		(LPOVERLAPPED)&varOverLapped);          // synchronous I/O
	printf("bResult:%b", bResult);
	DWORD wait_code = WaitForSingleObject(varObjectHandle, 0);

	SetEvent(varObjectHandle);
	ResetEvent(varObjectHandle);
	CloseHandle(varObjectHandle);
	return (bResult);

}

//Dll模块的入口函数
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

