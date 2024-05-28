#include <ntifs.h>
#include "ProcessInformation.h"
#include "peb.h"


#define DEVICE_NAME L"\\device\\ProcessProtect"
#define LINK_NAME L"\\dosdevices\\ProcessProtect"


#define IOCTRL_BASE 0x800

#define MYIOCTRL_CODE(i) \
	CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTRL_BASE+i, METHOD_BUFFERED,FILE_ANY_ACCESS)

#define CTL_START MYIOCTRL_CODE(0)
#define CTL_REBOOT MYIOCTRL_CODE(1)
#define CTL_CHECK_PE MYIOCTRL_CODE(2)
#define CTL_BYE MYIOCTRL_CODE(3)


#define XOR_SWAP_STRING_ELEMENTS(arr1, arr2, size) \
    do { \
        for (size_t i = 0; i < size; ++i) { \
            (arr1)[i] = (arr1)[i] ^ (arr2)[i]; \
            (arr2)[i] = (arr1)[i] ^ (arr2)[i]; \
            (arr1)[i] = (arr1)[i] ^ (arr2)[i]; \
        } \
    } while (0)

//进程重启相关申明
#define ACCESS_ZERO (*(volatile int *)0 = 0)

enum FIRMWARE_REENTRY
{
	HalHaltRoutine,
	HalPowerDownRoutine,
	HalRestartRoutine,
	HalRebootRoutine,
	HalInteractiveModeRoutine,
	HalMaximumRoutine
} FIRMWARE_REENTRY, * PFIRMWARE_REENTRY;


typedef struct _SAVE_STRUCT
{
	unsigned int g_save_pid;
	WCHAR str[50];
}SAVE_STRUCT, * PSAVE_STRUCT;

typedef struct _DEVICE_EXTENSION {
	KDPC g_dpc;
	KTIMER g_timer;
	int g_flag;
	int g_Shutdown_flag;
	SAVE_STRUCT g_save;
	KSPIN_LOCK g_SpinLock;
} DEVICE_EXTENSION, * PDEVICE_EXTENSION;

/*
KDPC g_dpc;
KTIMER g_timer;
int g_flag=0;
int g_Shutdown_flag = 0;
*/


//KSPIN_LOCK GlobalSpinLock;


PVOID pRegistrationHandle;
//进程管理器详细界面结束代码
#define PROCESS_TERMINATE_0       0x1001
//taskkill指令结束代码
#define PROCESS_TERMINATE_1       0x0001 
//taskkill指令加/f参数强杀进程结束码
#define PROCESS_KILL_F			  0x1401
//进程管理器结束代码
#define PROCESS_TERMINATE_2       0x1041
// _LDR_DATA_TABLE_ENTRY ,注意32位与64位的对齐大小
#ifdef _WIN64
typedef struct _LDR_DATA
{
	LIST_ENTRY listEntry;
	ULONG64 __Undefined1;
	ULONG64 __Undefined2;
	ULONG64 __Undefined3;
	ULONG64 NonPagedDebugInfo;
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING path;
	UNICODE_STRING name;
	ULONG   Flags;
}LDR_DATA, * PLDR_DATA;
#else
typedef struct _LDR_DATA
{
	LIST_ENTRY listEntry;
	ULONG unknown1;
	ULONG unknown2;
	ULONG unknown3;
	ULONG unknown4;
	ULONG unknown5;
	ULONG unknown6;
	ULONG unknown7;
	UNICODE_STRING path;
	UNICODE_STRING name;
	ULONG   Flags;
}LDR_DATA, * PLDR_DATA;
#endif


typedef   enum   _SHUTDOWN_ACTION {
	ShutdownNoReboot,         //关机不重启
	ShutdownReboot,             //关机并重启
	ShutdownPowerOff          //关机并关闭电源
}SHUTDOWN_ACTION;




typedef void (*VoidFunctionPointer)();

VOID HalReturnToFirmware(
	IN enum FIRMWARE_REENTRY  Routine
);

NTSTATUS NTAPI NtShutdownSystem(IN SHUTDOWN_ACTION Action);




EXTERN_C NTSTATUS LogpSleep(_In_ LONG Millisecond) {
	PAGED_CODE();
	LARGE_INTEGER interval = { 0 };
	interval.QuadPart = -(10000 * Millisecond);  // msec
	return KeDelayExecutionThread(KernelMode, FALSE, &interval);
}



#if DBG
EXTERN_C void AsmInt3();
#endif



NTSTATUS EnumSystemProcess(IN PWCH TargetProcessName);

PUCHAR NTAPI PsGetProcessImageFileName(__in PEPROCESS Process);

NTSTATUS InitTargetProcessNameR(IN PSAVE_STRUCT SaveBuff, PDEVICE_OBJECT pObject);


NTSTATUS NTAPI NtQueryInformationProcess(_In_ HANDLE 	ProcessHandle,
	_In_ PROCESSINFOCLASS 	ProcessInformationClass,
	_Out_ PVOID 	ProcessInformation,
	_In_ ULONG 	ProcessInformationLength,
	_Out_opt_ PULONG 	ReturnLength
);



VOID IsFun(PDEVICE_OBJECT pObject);
VOID IsProcessActive(PDEVICE_OBJECT pObject);

VOID ShutDownRuntime(PDEVICE_OBJECT pObject);
VOID CreateSystemThreadCommonInterface(VoidFunctionPointer function, PDEVICE_OBJECT pObject);
VOID CheckPE();
VOID ShutDownRuntimeDirect();
VOID CallBackRegedit(PDRIVER_OBJECT pDriver, PDEVICE_EXTENSION deviceExtension);



// 定义导出
NTKERNELAPI PVOID NTAPI PsGetProcessPeb(_In_ PEPROCESS Process);

#pragma LOCKEDCODE
void DpcRoutine(
	PKDPC pDpc,
	PVOID DeferredContext,
	PVOID SysArg1,
	PVOID SysArg2) {
	KIRQL oldIrql;
	KdPrint(("In DpcRoutine.\n"));

	PDEVICE_EXTENSION deviceExtension = (PDEVICE_EXTENSION)DeferredContext;

	KeAcquireSpinLock(&deviceExtension->g_SpinLock, &oldIrql);
	deviceExtension->g_Shutdown_flag = 1;
	KeReleaseSpinLock(&deviceExtension->g_SpinLock, oldIrql);
}

OB_PREOP_CALLBACK_STATUS PreProcessHandle(
	PVOID RegistrationContext,
	POB_PRE_OPERATION_INFORMATION pOperationInformation
)
{

	//UNREFERENCED_PARAMETER(RegistrationContext);

	PDEVICE_EXTENSION deviceExtension = (PDEVICE_EXTENSION)RegistrationContext;
	HANDLE pid = PsGetProcessId((PEPROCESS)pOperationInformation->Object);
	

	if (pid!=0 && pid == deviceExtension->g_save.g_save_pid)
	{
		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		{
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)//进程终止
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)//openprocess
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)//内存读
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)//内存写
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
			}
		}
	}
	return OB_PREOP_SUCCESS;

}


NTSTATUS DispatchCommon(PDEVICE_OBJECT pObject, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS; // 返回给应用层
	pIrp->IoStatus.Information = 0; // 读写字节数

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS; // 返回给内核层IO管理器
}

NTSTATUS CreateDispatch(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}




NTSTATUS DispatchIoctrl(PDEVICE_OBJECT pObject, PIRP pIrp)
{
	ULONG uIoctrlCode = 0;
	PVOID pInputBuff = NULL;
	PVOID pOutputBuff = NULL;

	ULONG uInputLength = 0;
	ULONG uOutputLength = 0;
	PIO_STACK_LOCATION pStack = NULL;

	pInputBuff = pOutputBuff = pIrp->AssociatedIrp.SystemBuffer;

	pStack = IoGetCurrentIrpStackLocation(pIrp);
	uInputLength = pStack->Parameters.DeviceIoControl.InputBufferLength;
	uOutputLength = pStack->Parameters.DeviceIoControl.OutputBufferLength;

	
	uIoctrlCode = pStack->Parameters.DeviceIoControl.IoControlCode;
	switch (uIoctrlCode)
	{
	case CTL_START://判断RTCDesktop.exe是否存在
		InitTargetProcessNameR(pOutputBuff, pObject);
		IsProcessActive(pObject);
		CreateSystemThreadCommonInterface(ShutDownRuntime, pObject);
		break;
		
	case CTL_REBOOT://直接重启接口

#if DBG
		AsmInt3();
#endif
		CreateSystemThreadCommonInterface(ShutDownRuntimeDirect, pObject);
		break;
	case CTL_CHECK_PE://检测指纹是否符合，不符合重启

#if DBG
		AsmInt3();
#endif
		KdPrint(("in CTL_CHECK_PE\n"));

		CreateSystemThreadCommonInterface(CheckPE, pObject);

		break;
	case CTL_BYE:
		DbgPrint("Goodbye iocontrol\n");
		break;
	default:
		DbgPrint("Unknown iocontrol\n");

	}

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;

}


VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	
	DbgPrint("Driver unloaded\n");


	if (NULL != pRegistrationHandle)
	{
		KdPrint(("卸载回调成功\n"));
		ObUnRegisterCallbacks(pRegistrationHandle);
		pRegistrationHandle = NULL;
	}


	PDEVICE_OBJECT pDeviceObject = pDriverObject->DeviceObject;

	// 删除所有设备对象
	while (pDeviceObject != NULL) {
		PDEVICE_EXTENSION pDeviceExtension = (PDEVICE_EXTENSION)pDeviceObject->DeviceExtension;
		
		// 释放设备扩展中的资源
		// 例如：如果有定时器，调用 KeCancelTimer(&pDeviceExtension->MyTimer);

		// 删除符号链接（如果有）
		UNICODE_STRING uLinkName;
		RtlInitUnicodeString(&uLinkName, LINK_NAME);
		IoDeleteSymbolicLink(&uLinkName);

		// 获取下一个设备对象
		PDEVICE_OBJECT pNextDevice = pDeviceObject->NextDevice;
		IoDeleteDevice(pDeviceObject);
		pDeviceObject = pNextDevice;
	}


	//NtShutdownSystem(ShutdownReboot);
	//ACCESS_ZERO;
	//HalReturnToFirmware(HalPowerDownRoutine);
	HalReturnToFirmware(HalRebootRoutine);
}


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject,
	PUNICODE_STRING pRegPath)
{
/*
#if DBG
	AsmInt3();
#endif
*/
	UNICODE_STRING uDeviceName = { 0 };
	UNICODE_STRING uLinkName = { 0 };
	NTSTATUS ntStatus = 0;
	PDEVICE_OBJECT pDeviceObject = NULL;
	ULONG i = 0;

	DbgPrint("Driver load begin\n");

	RtlInitUnicodeString(&uDeviceName, DEVICE_NAME);
	RtlInitUnicodeString(&uLinkName, LINK_NAME);

	ntStatus = IoCreateDevice(pDriverObject,
		sizeof(DEVICE_EXTENSION), &uDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDeviceObject);

	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("IoCreateDevice failed:%x", ntStatus);
		return ntStatus;
	}

	//DO_BUFFERED_IO规定R3和R0之间read和write通信的方式：
	//1,buffered io
	//2,direct io
	//3,neither io
	pDeviceObject->Flags |= DO_BUFFERED_IO;

	ntStatus = IoCreateSymbolicLink(&uLinkName, &uDeviceName);
	if (!NT_SUCCESS(ntStatus))
	{
		IoDeleteDevice(pDeviceObject);
		DbgPrint("IoCreateSymbolicLink failed:%x\n", ntStatus);
		return ntStatus;
	}

	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION + 1; i++)
	{
		pDriverObject->MajorFunction[i] = DispatchCommon;
	}
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctrl;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = CreateDispatch;
	pDriverObject->DriverUnload = DriverUnload;
	

	// 清零设备扩展
	PDEVICE_EXTENSION deviceExtension = (PDEVICE_EXTENSION)pDeviceObject->DeviceExtension;
	RtlZeroMemory(deviceExtension, sizeof(DEVICE_EXTENSION));

	// 初始化设备扩展中的变量
	KeInitializeDpc(&deviceExtension->g_dpc, DpcRoutine, deviceExtension); // 初始化KDPC对象并设置回调函数
	KeInitializeTimer(&deviceExtension->g_timer); // 初始化定时器对象
	deviceExtension->g_flag = 0;
	deviceExtension->g_Shutdown_flag = 0;
	SAVE_STRUCT g_save = { 0 };
	KeInitializeSpinLock(&deviceExtension->g_SpinLock);


	//CallBackRegedit(pDriverObject);

	DbgPrint("Driver load ok!\n");

	return STATUS_SUCCESS;
}

VOID IsProcessActive(PDEVICE_OBJECT pObject)
{
	KdPrint(("In IsProcessActive.\n"));
	HANDLE hThread;
	//PVOID objtowait = 0;

	NTSTATUS dwStatus =
		PsCreateSystemThread(
			&hThread,
			0,
			NULL,
			(HANDLE)0,
			NULL,
			IsFun,
			pObject
		);

	NTSTATUS st;
	if ((KeGetCurrentIrql()) != PASSIVE_LEVEL)
	{
		st = KfRaiseIrql(PASSIVE_LEVEL);

	}
	if ((KeGetCurrentIrql()) != PASSIVE_LEVEL)
	{

		return;
	}
	KdPrint(("Out IsProcessActive.\n"));

	/*
	ObReferenceObjectByHandle(
		hThread,
		THREAD_ALL_ACCESS,
		NULL,
		KernelMode,
		&objtowait,
		NULL
	);

	st = KeWaitForSingleObject(objtowait, Executive, KernelMode, FALSE, NULL); //NULL表示无限期等待.
	*/

	return;
}

VOID IsFun(PDEVICE_OBJECT pObject)
{
	KdPrint(("In IsFun.\n"));

	// 遍历进程

	NTSTATUS status = STATUS_SUCCESS;
	ULONG i = 0;
	PEPROCESS pEProcess = NULL;
	PCHAR pszProcessName = NULL;
	KIRQL oldIrql;
	LARGE_INTEGER dueTime;
	dueTime.QuadPart = -10000000*60*3;  

	//KeSetTimer(&g_timer, dueTime, &dpc);
	
	PDEVICE_EXTENSION deviceExtension = pObject->DeviceExtension;

	for (;;) 
	{
		if (EnumSystemProcess(deviceExtension->g_save.str) == STATUS_OK)
		{
			KeAcquireSpinLock(&deviceExtension->g_SpinLock, &oldIrql);
			KeCancelTimer(&deviceExtension->g_timer); // 取消DPC定时器
			deviceExtension->g_flag = 0;
			KeReleaseSpinLock(&deviceExtension->g_SpinLock, oldIrql);

		}
		else
		{
			KeAcquireSpinLock(&deviceExtension->g_SpinLock, &oldIrql);
			if (deviceExtension->g_flag == 0)
			{
				KeSetTimer(&deviceExtension->g_timer, dueTime, &deviceExtension->g_dpc);
				deviceExtension->g_flag = 1;
			}
			KeReleaseSpinLock(&deviceExtension->g_SpinLock, oldIrql);
		}
		LogpSleep(5);
	
	}
	
	//重启
	//NtShutdownSystem(ShutdownReboot);

}


//枚举所有进程判断保护的进程是否存在
NTSTATUS EnumSystemProcess(IN PWCH TargetProcessName)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PSYSTEM_PROCESSES pProcessInfo = NULL;
	PSYSTEM_PROCESSES pTemp = NULL;//这个留作以后释放指针的时候用。
	ULONG ulNeededSize;
	ULONG ulNextOffset;

	//初始化 UnicodeStringTargetProcessName
	UNICODE_STRING UnicodeStringTargetProcessName;
	RtlInitUnicodeString(&UnicodeStringTargetProcessName, TargetProcessName);

	//第一次使用肯定是缓冲区不够，不过本人在极少数的情况下第二次也会出现不够，所以用while循环
	status = ZwQuerySystemInformation(SystemProcessesAndThreadsInformation, pProcessInfo, 0, &ulNeededSize);
	while (STATUS_INFO_LENGTH_MISMATCH == status)
	{
		pProcessInfo = ExAllocatePoolWithTag(NonPagedPool, ulNeededSize, '1aes');
		pTemp = pProcessInfo;
		if (NULL == pProcessInfo)
		{
			//KdPrint(("[allocatePoolWithTag] failed"));
			return status;
		}
		status = ZwQuerySystemInformation(SystemProcessesAndThreadsInformation, pProcessInfo, ulNeededSize, &ulNeededSize);
	}
	if (NT_SUCCESS(status))
	{
		//KdPrint(("[ZwQuerySystemInformation]success bufferSize:%x", ulNeededSize));
	}
	else
	{
		//KdPrint(("[error]:++++%d", status));
		return status;
	}

	do
	{
		//KdPrint(("[imageName Buffer]:%08x", pProcessInfo->ProcessName.Buffer));

		if (MmIsAddressValid(pProcessInfo->ProcessName.Buffer) && NULL != pProcessInfo)
		{
			
			if (RtlEqualUnicodeString(&UnicodeStringTargetProcessName, &pProcessInfo->ProcessName, TRUE))
			{

				status = STATUS_OK;

			}

			//KdPrint(("[ProcessID]:%d , [imageName]:%ws", pProcessInfo->ProcessId, pProcessInfo->ProcessName.Buffer));
		}

		ulNextOffset = pProcessInfo->NextEntryDelta;
		pProcessInfo = (PSYSTEM_PROCESSES)((PUCHAR)pProcessInfo + pProcessInfo->NextEntryDelta);

	} while (ulNextOffset != 0);

	ExFreePoolWithTag(pTemp, '1aes');

	return status;
}


NTSTATUS InitTargetProcessNameR(IN PSAVE_STRUCT SaveBuff, PDEVICE_OBJECT pObject)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	KIRQL oldIrql;
	if (SaveBuff == NULL)return STATUS_UNSUCCESSFUL;

	PDEVICE_EXTENSION deviceExtension = (PDEVICE_EXTENSION)pObject->DeviceExtension;

	KeAcquireSpinLock(&deviceExtension->g_SpinLock, &oldIrql);
	deviceExtension->g_save.g_save_pid = SaveBuff->g_save_pid;
	RtlMoveMemory(deviceExtension->g_save.str, SaveBuff->str, 50);
	KeReleaseSpinLock(&deviceExtension->g_SpinLock, oldIrql);

	if (deviceExtension->g_save.str == NULL)return STATUS_UNSUCCESSFUL;

	return ntStatus;
}




VOID ShutDownRuntime(PDEVICE_OBJECT pObject)
{
	KdPrint(("In ShutDownRuntime.\n"));
	PDEVICE_EXTENSION deviceExtension = (PDEVICE_EXTENSION)pObject->DeviceExtension;

	while(deviceExtension->g_Shutdown_flag == 0)
	{
		LogpSleep(5);
	}
	KdPrint(("Call NtShutdownSystem.\n"));

		//NtShutdownSystem(ShutdownReboot);
		//ACCESS_ZERO;
		//HalReturnToFirmware(HalPowerDownRoutine);
		HalReturnToFirmware(HalRebootRoutine);
}


VOID ShutDownRuntimeDirect()
{
	
	KdPrint(("Call NtShutdownSystem.\n"));

	//NtShutdownSystem(ShutdownReboot);
	//ACCESS_ZERO;
	//HalReturnToFirmware(HalPowerDownRoutine);
	HalReturnToFirmware(HalRebootRoutine);
}


VOID CreateSystemThreadCommonInterface(VoidFunctionPointer function, PDEVICE_OBJECT pObject)
{
	HANDLE SD_hThread;
	//PVOID objtowait = 0;
	KdPrint(("In CreateSystemThreadCommonInterface.\n"));
	NTSTATUS dwStatus =
		PsCreateSystemThread(
			&SD_hThread,
			0,
			NULL,
			(HANDLE)0,
			NULL,
			function,
			pObject
		);

	NTSTATUS st;
	if ((KeGetCurrentIrql()) != PASSIVE_LEVEL)
	{
		st = KfRaiseIrql(PASSIVE_LEVEL);

	}
	if ((KeGetCurrentIrql()) != PASSIVE_LEVEL)
	{

		return;
	}
	KdPrint(("Out CreateSystemThreadCommonInterface.\n"));
}


VOID CheckPE()
{
	KdPrint(("in CheckPE.\n"));
	BOOLEAN bRetValue = TRUE;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS eproc = NULL;
	PPEB64 pPeb64 = NULL;
	const char* p = NULL; 
	KAPC_STATE kpc = { 0 };
	//KIRQL OldIrql;
	PVOID addressToRead = NULL;
	UCHAR valueAtAddress;

	__try
	{
		for (size_t i = 0; i < 0xffff; i = i % 0xfffe, i++)
		{

			// 获取 EPROCESS 结构
			status = PsLookupProcessByProcessId((HANDLE)i, &eproc);
			
			if (status == STATUS_SUCCESS && eproc != NULL)
			{
				// 获取进程名

				p = (const char*)(PUCHAR)eproc + 0x5a8;
				if (_stricmp(p, "RTCDesktop.exe") == 0)
				{
					KdPrint(("找到同名RTCDesktop.exe进程.\n"));
					// 获取 PEB
					pPeb64 = (PPEB64)PsGetProcessPeb(eproc);
					if (pPeb64 != NULL)
					{
						// 对读取进行探测
						ProbeForRead(pPeb64, sizeof(PEB64), 1);
						KdPrint(("附加到指定进程.\n"));
						// 附加进程
						KeStackAttachProcess(eproc, &kpc);

						//KeAcquireSpinLock(&GlobalSpinLock, &OldIrql);
#if DBG
						DbgPrint("进程基地址: 0x%p \n", pPeb64->ImageBaseAddress);
#endif
						addressToRead = (PVOID)((ULONG_PTR)pPeb64->ImageBaseAddress + 0x15);
						// 探测读取指定地址的内存
						ProbeForRead(addressToRead, sizeof(UCHAR), sizeof(UCHAR));

						// 读取指定地址的值
						
						RtlCopyMemory(&valueAtAddress, addressToRead, sizeof(UCHAR));

						// 判断值是否为 0xFF
						if (valueAtAddress == 0xFF)
						{
							KdPrint(("PE值是 0xFF.\n"));
							bRetValue = TRUE;
						}
						else
						{
							//存在伪装进程
							KdPrint(("存在伪装进程.\n"));
							//NtShutdownSystem(ShutdownReboot);
							//ACCESS_ZERO;
							//HalReturnToFirmware(HalPowerDownRoutine);
							HalReturnToFirmware(HalRebootRoutine);

						}

						//KeReleaseSpinLock(&GlobalSpinLock, OldIrql);

						// 脱离进程
						KeUnstackDetachProcess(&kpc);
						KdPrint(("脱离进程.\n"));
					}

					ObDereferenceObject(eproc);
				}
			}

			LogpSleep(5);

		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		bRetValue = FALSE;
	}

	KdPrint(("Out CheckPE.\n"));
}

VOID CallBackRegedit(PDRIVER_OBJECT pDriver, PDEVICE_EXTENSION deviceExtension)
{

	OB_OPERATION_REGISTRATION oor;
	OB_CALLBACK_REGISTRATION ocr;
	PLDR_DATA pld;//指向_LDR_DATA_TABLE_ENTRY结构体的指针

	//初始化
	pRegistrationHandle = 0;
	RtlZeroMemory(&oor, sizeof(OB_OPERATION_REGISTRATION));
	RtlZeroMemory(&ocr, sizeof(OB_CALLBACK_REGISTRATION));


	//初始化 OB_OPERATION_REGISTRATION 

	//设置监听的对象类型
	oor.ObjectType = PsProcessType;
	//设置监听的操作类型
	oor.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	//设置操作发生前执行的回调
	oor.PreOperation = PreProcessHandle;
	//设置操作发生前执行的回调
	//oor.PostOperation = ?

	//初始化 OB_CALLBACK_REGISTRATION 

	// 设置版本号，必须为OB_FLT_REGISTRATION_VERSION
	ocr.Version = OB_FLT_REGISTRATION_VERSION;
	//设置自定义参数，可以为NULL
	ocr.RegistrationContext = deviceExtension;
	// 设置回调函数个数
	ocr.OperationRegistrationCount = 1;
	//设置回调函数信息结构体,如果个数有多个,需要定义为数组.
	ocr.OperationRegistration = &oor;
	RtlInitUnicodeString(&ocr.Altitude, L"321000"); // 设置加载顺序



	// 绕过MmVerifyCallbackFunction。
	pld = (PLDR_DATA)pDriver->DriverSection;
	pld->Flags |= 0x20;


	if (NT_SUCCESS(ObRegisterCallbacks(&ocr, &pRegistrationHandle)))
	{
		KdPrint(("ObRegisterCallbacks注册成功"));
	}
	else
	{
		KdPrint(("ObRegisterCallbacks失败"));
	}

}


