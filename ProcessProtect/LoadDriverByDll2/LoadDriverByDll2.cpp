// LoadDriverByDll.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>
#include "string.h"
//_______________________//
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <conio.h>
#include <ctype.h>
#include <iostream>
#include <windows.h>

using namespace std;

extern "C" typedef BOOL(__cdecl* LoadDriver)(char* lpszDriverName, char* lpszDriverPath);
extern "C" typedef BOOL(__cdecl* UnloadDriver)(char* szSvrName);
extern "C" typedef BOOL(__cdecl* DeviceControl)(_In_ char* lpszDriverName, _In_ LPWSTR ProtectProcessName, _In_ ULONG_PTR ProtectProcessPid);
extern "C" typedef BOOL(__cdecl* PsProtectBegin)(char* lpszDriverName);
extern "C" typedef BOOL(__cdecl* DeviceControlCommonInterface)(char* lpszDriverName, DWORD control_code);


#define IOCTRL_BASE 0x800

#define MYIOCTRL_CODE(i) \
	CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTRL_BASE+i, METHOD_BUFFERED,FILE_ANY_ACCESS)

#define CTL_START MYIOCTRL_CODE(0)
#define CTL_REBOOT MYIOCTRL_CODE(1)
#define CTL_CHECK_PE MYIOCTRL_CODE(2)
#define CTL_BYE MYIOCTRL_CODE(3)



typedef struct _SAVE_STRUCT
{
	unsigned int g_save_pid;
	WCHAR str[50];
}SAVE_STRUCT, * PSAVE_STRUCT;

SAVE_STRUCT g_save = { 0 };


int main(int argc, char* argv[])
{
	HMODULE _hDllInst = LoadLibraryW(L"LoadDriverByPs.dll");
	LoadDriver LoadDriverFunction = (LoadDriver)GetProcAddress(_hDllInst, "LoadDriver");
	UnloadDriver UnloadDriverFunction = (UnloadDriver)GetProcAddress(_hDllInst, "UnloadDriver");
	DeviceControl DeviceControlFunction = (DeviceControl)GetProcAddress(_hDllInst, "DeviceControl");

	//PsProtectBegin PSPROTECTBEGIN = (PsProtectBegin)GetProcAddress(_hDllInst, "PsProtectBegin");

	LoadDriverFunction((char*)"ProcessProtect", (char*)"ProcessProtect.sys");//1.加载驱动

	//CTL_START控制指令，检测RTCDesktop.exe是否存在，不存在则3min后重启
	DeviceControlFunction((char*)"ProcessProtect", (LPWSTR)L"RTCDesktop.exe", GetCurrentProcessId());

	DeviceControlCommonInterface f = (DeviceControlCommonInterface)GetProcAddress(_hDllInst, "DeviceControlCommonInterface");

	f((char*)"ProcessProtect", CTL_CHECK_PE);//CTL_CHECK_PE控制指令，检测是否存在伪装进程,如果存在，则会直接重启

	//f((char*)"ProcessProtect", CTL_REBOOT);//CTL_REBOOT控制指令,调用将会直接重启
	
	

	//PSPROTECTBEGIN((char*)"ProcessProtect");
	//UnloadDriverFunction((char*)"ProcessProtect");

	system("pause");
	//FreeLibrary(_hDllInst);
}


