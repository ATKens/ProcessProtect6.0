#pragma once
#include <windows.h>
extern "C" __declspec(dllexport) BOOL __cdecl LoadDriver(char* lpszDriverName, char* lpszDriverPath);
extern "C" __declspec(dllexport) BOOL __cdecl UnloadDriver(char* szSvrName);
extern "C" __declspec(dllexport) BOOL __cdecl DeviceControl(_In_ char* lpszDriverName, _In_ LPWSTR ProtectProcessName, _In_ ULONG_PTR ProtectProcessPid);
extern "C" __declspec(dllexport) int __cdecl  GetProcessState(DWORD dwProcessID);
extern "C" __declspec(dllexport) BOOL __cdecl PsProtectBegin(char* lpszDriverName);
extern "C" __declspec(dllexport) BOOL __cdecl DeviceControlCommonInterface(char* lpszDriverName,DWORD control_code);

extern "C" __declspec(dllexport) BOOL __cdecl DeviceControlHeartbeat(char* lpszDriverName);
//extern "C" __declspec(dllexport) BOOLEAN __cdecl CheckPE(IN WCHAR * filepath);