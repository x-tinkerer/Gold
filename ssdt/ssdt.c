//SSDT.c

//#include <ntifs.h>
#include <ntddk.h>
#include <ntstatus.h>
#include <wdm.h>
#include <ntstrsafe.h>
#include <windef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "tdiinfo.h"
#include "ssdt.h"

extern PMYSSDT    KeServiceDescriptorTable;
/*  Server 2003 Wrk 

nt!PEPROCESS
Ptr32    +0x000 Pcb              : _KPROCESS
   +0x078 ProcessLock      : _EX_PUSH_LOCK
   +0x080 CreateTime       : _LARGE_INTEGER
   +0x088 ExitTime         : _LARGE_INTEGER
   +0x090 RundownProtect   : _EX_RUNDOWN_REF
   +0x094 UniqueProcessId  : Ptr32 Void
   +0x098 ActiveProcessLinks : _LIST_ENTRY
   +0x0a0 QuotaUsage       : [3] Uint4B
   +0x0ac QuotaPeak        : [3] Uint4B
   +0x0b8 CommitCharge     : Uint4B
   +0x0bc PeakVirtualSize  : Uint4B
   +0x0c0 VirtualSize      : Uint4B
   +0x0c4 SessionProcessLinks : _LIST_ENTRY
   +0x0cc DebugPort        : Ptr32 Void
   +0x0d0 ExceptionPort    : Ptr32 Void
   +0x0d4 ObjectTable      : Ptr32 _HANDLE_TABLE
   +0x0d8 Token            : _EX_FAST_REF
   +0x0dc WorkingSetPage   : Uint4B
   +0x0e0 AddressCreationLock : _KGUARDED_MUTEX
   +0x100 HyperSpaceLock   : Uint4B
   +0x104 ForkInProgress   : Ptr32 _ETHREAD
   +0x108 HardwareTrigger  : Uint4B
   +0x10c PhysicalVadRoot  : Ptr32 _MM_AVL_TABLE
   +0x110 CloneRoot        : Ptr32 Void
   +0x114 NumberOfPrivatePages : Uint4B
   +0x118 NumberOfLockedPages : Uint4B
   +0x11c Win32Process     : Ptr32 Void
   +0x120 Job              : Ptr32 _EJOB
   +0x124 SectionObject    : Ptr32 Void
   +0x128 SectionBaseAddress : Ptr32 Void
   +0x12c QuotaBlock       : Ptr32 _EPROCESS_QUOTA_BLOCK
   +0x130 WorkingSetWatch  : Ptr32 _PAGEFAULT_HISTORY
   +0x134 Win32WindowStation : Ptr32 Void
   +0x138 InheritedFromUniqueProcessId : Ptr32 Void
   +0x13c LdtInformation   : Ptr32 Void
   +0x140 VadFreeHint      : Ptr32 Void
   +0x144 VdmObjects       : Ptr32 Void
   +0x148 DeviceMap        : Ptr32 Void
   +0x14c Spare0           : [3] Ptr32 Void
   +0x158 PageDirectoryPte : _HARDWARE_PTE_X86
   +0x158 Filler           : Uint8B
   +0x160 Session          : Ptr32 Void
   +0x164 ImageFileName    : [16] UChar
   +0x174 JobLinks         : _LIST_ENTRY
   +0x17c LockedPagesList  : Ptr32 Void
   +0x180 ThreadListHead   : _LIST_ENTRY
   +0x188 SecurityPort     : Ptr32 Void
   +0x18c PaeTop           : Ptr32 Void
   +0x190 ActiveThreads    : Uint4B
   +0x194 GrantedAccess    : Uint4B
   +0x198 DefaultHardErrorProcessing : Uint4B
   +0x19c LastThreadExitStatus : Int4B
   +0x1a0 Peb              : Ptr32 _PEB
   +0x1a4 PrefetchTrace    : _EX_FAST_REF
   +0x1a8 ReadOperationCount : _LARGE_INTEGER
   +0x1b0 WriteOperationCount : _LARGE_INTEGER
   +0x1b8 OtherOperationCount : _LARGE_INTEGER
   +0x1c0 ReadTransferCount : _LARGE_INTEGER
   +0x1c8 WriteTransferCount : _LARGE_INTEGER
   +0x1d0 OtherTransferCount : _LARGE_INTEGER
   +0x1d8 CommitChargeLimit : Uint4B
   +0x1dc CommitChargePeak : Uint4B
   +0x1e0 AweInfo          : Ptr32 Void
   +0x1e4 SeAuditProcessCreationInfo : _SE_AUDIT_PROCESS_CREATION_INFO
   +0x1e8 Vm               : _MMSUPPORT
   +0x230 MmProcessLinks   : _LIST_ENTRY
   +0x238 ModifiedPageCount : Uint4B
   +0x23c JobStatus        : Uint4B
   +0x240 Flags            : Uint4B
   +0x240 CreateReported   : Pos 0, 1 Bit
   +0x240 NoDebugInherit   : Pos 1, 1 Bit
   +0x240 ProcessExiting   : Pos 2, 1 Bit
   +0x240 ProcessDelete    : Pos 3, 1 Bit
   +0x240 Wow64SplitPages  : Pos 4, 1 Bit
   +0x240 VmDeleted        : Pos 5, 1 Bit
   +0x240 OutswapEnabled   : Pos 6, 1 Bit
   +0x240 Outswapped       : Pos 7, 1 Bit
   +0x240 ForkFailed       : Pos 8, 1 Bit
   +0x240 Wow64VaSpace4Gb  : Pos 9, 1 Bit
   +0x240 AddressSpaceInitialized : Pos 10, 2 Bits
   +0x240 SetTimerResolution : Pos 12, 1 Bit
   +0x240 BreakOnTermination : Pos 13, 1 Bit
   +0x240 SessionCreationUnderway : Pos 14, 1 Bit
   +0x240 WriteWatch       : Pos 15, 1 Bit
   +0x240 ProcessInSession : Pos 16, 1 Bit
   +0x240 OverrideAddressSpace : Pos 17, 1 Bit
   +0x240 HasAddressSpace  : Pos 18, 1 Bit
   +0x240 LaunchPrefetched : Pos 19, 1 Bit
   +0x240 InjectInpageErrors : Pos 20, 1 Bit
   +0x240 VmTopDown        : Pos 21, 1 Bit
   +0x240 ImageNotifyDone  : Pos 22, 1 Bit
   +0x240 PdeUpdateNeeded  : Pos 23, 1 Bit
   +0x240 VdmAllowed       : Pos 24, 1 Bit
   +0x240 SmapAllowed      : Pos 25, 1 Bit
   +0x240 CreateFailed     : Pos 26, 1 Bit
   +0x240 DefaultIoPriority : Pos 27, 3 Bits
   +0x240 Spare1           : Pos 30, 1 Bit
   +0x240 Spare2           : Pos 31, 1 Bit
   +0x244 ExitStatus       : Int4B
   +0x248 NextPageColor    : Uint2B
   +0x24a SubSystemMinorVersion : UChar
   +0x24b SubSystemMajorVersion : UChar
   +0x24a SubSystemVersion : Uint2B
   +0x24c PriorityClass    : UChar
   +0x250 VadRoot          : _MM_AVL_TABLE
   +0x270 Cookie           : Uint4B

*/

/*
nt!PETHREAD
Ptr32    +0x000 Tcb              : _KTHREAD
   +0x1b8 CreateTime       : _LARGE_INTEGER
   +0x1c0 ExitTime         : _LARGE_INTEGER
   +0x1c0 LpcReplyChain    : _LIST_ENTRY
   +0x1c0 KeyedWaitChain   : _LIST_ENTRY
   +0x1c8 ExitStatus       : Int4B
   +0x1c8 OfsChain         : Ptr32 Void
   +0x1cc PostBlockList    : _LIST_ENTRY
   +0x1d4 TerminationPort  : Ptr32 _TERMINATION_PORT
   +0x1d4 ReaperLink       : Ptr32 _ETHREAD
   +0x1d4 KeyedWaitValue   : Ptr32 Void
   +0x1d8 ActiveTimerListLock : Uint4B
   +0x1dc ActiveTimerListHead : _LIST_ENTRY
   +0x1e4 Cid              : _CLIENT_ID
   +0x1ec LpcReplySemaphore : _KSEMAPHORE
   +0x1ec KeyedWaitSemaphore : _KSEMAPHORE
   +0x200 LpcReplyMessage  : Ptr32 Void
   +0x200 LpcWaitingOnPort : Ptr32 Void
   +0x204 ImpersonationInfo : Ptr32 _PS_IMPERSONATION_INFORMATION
   +0x208 IrpList          : _LIST_ENTRY
   +0x210 TopLevelIrp      : Uint4B
   +0x214 DeviceToVerify   : Ptr32 _DEVICE_OBJECT
   +0x218 ThreadsProcess   : Ptr32 _EPROCESS
   +0x21c StartAddress     : Ptr32 Void
   +0x220 Win32StartAddress : Ptr32 Void
   +0x220 LpcReceivedMessageId : Uint4B
   +0x224 ThreadListEntry  : _LIST_ENTRY
   +0x22c RundownProtect   : _EX_RUNDOWN_REF
   +0x230 ThreadLock       : _EX_PUSH_LOCK
   +0x234 LpcReplyMessageId : Uint4B
   +0x238 ReadClusterSize  : Uint4B
   +0x23c GrantedAccess    : Uint4B
   +0x240 CrossThreadFlags : Uint4B
   +0x240 Terminated       : Pos 0, 1 Bit
   +0x240 DeadThread       : Pos 1, 1 Bit
   +0x240 HideFromDebugger : Pos 2, 1 Bit
   +0x240 ActiveImpersonationInfo : Pos 3, 1 Bit
   +0x240 SystemThread     : Pos 4, 1 Bit
   +0x240 HardErrorsAreDisabled : Pos 5, 1 Bit
   +0x240 BreakOnTermination : Pos 6, 1 Bit
   +0x240 SkipCreationMsg  : Pos 7, 1 Bit
   +0x240 SkipTerminationMsg : Pos 8, 1 Bit
   +0x244 SameThreadPassiveFlags : Uint4B
   +0x244 ActiveExWorker   : Pos 0, 1 Bit
   +0x244 ExWorkerCanWaitUser : Pos 1, 1 Bit
   +0x244 MemoryMaker      : Pos 2, 1 Bit
   +0x244 KeyedEventInUse  : Pos 3, 1 Bit
   +0x248 SameThreadApcFlags : Uint4B
   +0x248 LpcReceivedMsgIdValid : Pos 0, 1 Bit
   +0x248 LpcExitThreadCalled : Pos 1, 1 Bit
   +0x248 AddressSpaceOwner : Pos 2, 1 Bit
   +0x248 OwnsProcessWorkingSetExclusive : Pos 3, 1 Bit
   +0x248 OwnsProcessWorkingSetShared : Pos 4, 1 Bit
   +0x248 OwnsSystemWorkingSetExclusive : Pos 5, 1 Bit
   +0x248 OwnsSystemWorkingSetShared : Pos 6, 1 Bit
   +0x248 OwnsSessionWorkingSetExclusive : Pos 7, 1 Bit
   +0x249 OwnsSessionWorkingSetShared : Pos 0, 1 Bit
   +0x249 ApcNeeded        : Pos 1, 1 Bit
   +0x24c ForwardClusterOnly : UChar
   +0x24d DisablePageFaultClustering : UChar
   +0x24e ActiveFaultCount : UChar

*/

//#define SystemHandleInformation  16
#define TCPUDP_FLAG   100
#define WIN2K_SOCKET_FLAG  0x1a //2k
#define WINXP_SOCKET_FLAG  0x1c //xp
#define WIN2K3_SOCKET_FLAG  0x1a //2k3
#define WIN2K_EPROCESS_NAMEOFFSET    0x1fc //2k
#define WINXP_EPROCESS_NAMEOFFSET    0x174 //xp
#define WIN2K3_EPROCESS_NAMEOFFSET   0x1fc //2k3

///////////////////////////不同的windows版本下面的偏移值不同
#define  EPROCESS_SIZE       0x274 //EPROCESS结构大小

#define  PEB_OFFSET          0x1A0    //Peb
#define  FILE_NAME_OFFSET    0x164    //ImageFileName
#define  PROCESS_LINK_OFFSET 0x098    //ActiveProcessLinks
#define  PROCESS_ID_OFFSET   0x094    //UniqueProcessId
#define  EXIT_TIME_OFFSET    0x088    //ExitTime

#define  OBJECT_HEADER_SIZE  0x018
#define  OBJECT_TYPE_OFFSET  0x008

#define PDE_INVALID 2 
#define PTE_INVALID 1 
#define VALID 0 
ULONG     pebAddress;         //PEB地址的前半部分
PEPROCESS pSystem;            //system进程
ULONG     pObjectTypeProcess; //进程对象类型

ULONG   VALIDpage(ULONG addr) ;  
BOOLEAN IsaRealProcess(ULONG i); 
VOID    WorkThread(IN PVOID pContext);
ULONG   GetPebAddress();          //得到PEB地址前半部分
VOID    EnumProcess();            //枚举进程
VOID    ShowProcess(ULONG pEProcess); //显示结果
///////////////////////////////////////////////////////

#define ObjectNameInformation  1
#define ObjectAllTypesInformation 3

#define ThreadProc			= 0x224   //ThreadListEntry
#define ThreadListHead		= 0x180   //ThreadListHead

#define MAX_MESSAGE (1024*64 - 16)

#define REGISTRY_POOL_TAG 'pRE'

typedef struct
{
	TCHAR  Message[0];
}MESSAGE,*PMESSAGE;

typedef struct
{
	TCHAR  Message[0];
}PORTMESSAGE,*PPORTMESSAGE;

//form WRK
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,             // obsolete...delete
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemMirrorMemoryInformation,
    SystemPerformanceTraceInformation,
    SystemObsolete0,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemVerifierAddDriverInformation,
    SystemVerifierRemoveDriverInformation,
    SystemProcessorIdleInformation,
    SystemLegacyDriverInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation,
    SystemTimeSlipNotification,
    SystemSessionCreate,
    SystemSessionDetach,
    SystemSessionInformation,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemVerifierThunkExtend,
    SystemSessionProcessInformation,
    SystemLoadGdiDriverInSystemSpace,
    SystemNumaProcessorMap,
    SystemPrefetcherInformation,
    SystemExtendedProcessInformation,
    SystemRecommendedSharedDataAlignment,
    SystemComPlusPackage,
    SystemNumaAvailableMemory,
    SystemProcessorPowerInformation,
    SystemEmulationBasicInformation,
    SystemEmulationProcessorInformation,
    SystemExtendedHandleInformation,
    SystemLostDelayedWriteInformation,
    SystemBigPoolInformation,
    SystemSessionPoolTagInformation,
    SystemSessionMappedViewInformation,
    SystemHotpatchInformation,
    SystemObjectSecurityMode,
    SystemWatchdogTimerHandler,
    SystemWatchdogTimerInformation,
    SystemLogicalProcessorInformation,
    SystemWow64SharedInformation,
    SystemRegisterFirmwareTableInformationHandler,
    SystemFirmwareTableInformation,
    SystemModuleInformationEx,
    SystemVerifierTriageInformation,
    SystemSuperfetchInformation,
    SystemMemoryListInformation,
    SystemFileCacheInformationEx,
    MaxSystemInfoClass  // MaxSystemInfoClass should always be the last enum
} SYSTEM_INFORMATION_CLASS;

//form wrk
typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

//form wrk
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER SpareLi1;
    LARGE_INTEGER SpareLi2;
    LARGE_INTEGER SpareLi3;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;
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
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;


typedef struct _SYSTEM_MODULE_INFORMATION { // Information Class 11
	ULONG Reserved[2];
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

#define ntohs(s) \
    ( ( ((s) >> 8) & 0x00FF ) | \
( ((s) << 8) & 0xFF00 ) )

typedef struct _TDI_CONNECTION_INFO { 
    ULONG          State; 
    ULONG          Event; 
    ULONG          TransmittedTsdus; 
    ULONG          ReceivedTsdus; 
    ULONG          TransmissionErrors; 
    ULONG          ReceiveErrors; 
    LARGE_INTEGER  Throughput; 
    LARGE_INTEGER  Delay; 
    ULONG          SendBufferSize; 
    ULONG          ReceiveBufferSize; 
    BOOLEAN        Unreliable; 
} TDI_CONNECTION_INFO, *PTDI_CONNECTION_INFO; 

typedef struct _TDI_CONNECTION_INFORMATION { 
    LONG   UserDataLength; 
    PVOID  UserData; 
    LONG   OptionsLength; 
    PVOID  Options; 
    LONG   RemoteAddressLength; 
    PVOID  RemoteAddress; 
} TDI_CONNECTION_INFORMATION, *PTDI_CONNECTION_INFORMATION; 

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG ProcessID;        //进程的标识ID
	UCHAR ObjectTypeNumber;        //对象类型
	UCHAR Flags;             //0x01 = PROTECT_FROM_CLOSE,0x02 = INHERIT
	USHORT Handle;             //对象句柄的数值
	PVOID  Object;            //对象句柄所指的内核对象地址 WinNT4/Windows2000是0x1A xp中是0x1c 2003中是
	ACCESS_MASK GrantedAccess;      //创建句柄时所准许的对象的访问权
}SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;
typedef NTSTATUS (*PSPTERMINATETHREADBYPOINTER)( PETHREAD, NTSTATUS);

typedef struct _CM_KEY_BODY {
    ULONG                   Type;
    PVOID   KeyControlBlock;
    PVOID   NotifyBlock;
    HANDLE                  ProcessID;        // the owner process
    LIST_ENTRY              KeyBodyList;    // key_nodes using the same kcb
} CM_KEY_BODY, *PCM_KEY_BODY;

typedef struct _REGISTRY_INFORMATION{
	CHAR ProcessName[256];
	CHAR KeyPath[256];
}REGISTRY_INFORMATION,*PREGISTRY_INFORMATION;

typedef struct _EVENT_INFORMATION{
	HANDLE hKernelSetEvent; // hUserWaitEvent
	HANDLE hKernelWaitEvent; // hUserSetEvent
}EVENT_INFORMATION,*PEVENT_INFORMATION;

PKEVENT EventKernelSet=NULL;
PKEVENT EventKernelWait=NULL;
ANSI_STRING astr;
ULONG PID;
BOOLEAN CreateAllowed=TRUE;
BOOLEAN CreateIsProgressing=FALSE;
LARGE_INTEGER Cookie;
BOOLEAN Prot=FALSE;
ULONG gProcessNameOffset;
#define NT_PROCNAMELEN  16
char aProcessName[256];

PEPROCESS	eProcess;
ULONG			processID;
PSPTERMINATETHREADBYPOINTER MyPspTerminateThreadByPointer;

typedef struct _log
{
	ULONG              Length;
	struct _log * Next;
	TCHAR              Message[MAX_MESSAGE];	
}LOG_BUF,*PLOG_BUF;


#define MUTEX_INIT(v)      KeInitializeMutex(&v,0)
#define MUTEX_P(v)         KeWaitForMutexObject(&v,Executive,KernelMode,FALSE,NULL)
#define MUTEX_V(v)         KeReleaseMutex(&v,FALSE)
/*********************************************
Process Information Block
**********************************************/
VOID
FreeLog(VOID);

VOID
NewLog(VOID);

PLOG_BUF 
OldestLog(VOID);

VOID
ResetLog(VOID);

VOID
UpdateLog(PTSTR);

KMUTEX       LogMutex;
PLOG_BUF         Log   = NULL;

ULONG            NumLog = 0;
ULONG            MaxLog = 16;
///////////////////////////////////
////////////////////////////////////////////////
BOOLEAN          IsHooked    = FALSE;




NTSYSAPI
NTSTATUS
NTAPI 
ObQueryNameString( 
				  IN PVOID Object, 
				  OUT POBJECT_NAME_INFORMATION  ObjectNameInfo, 
				  IN ULONG MaximumLength, 
				  OUT PULONG ActualLength 
    );
NTSYSAPI
NTSTATUS
NTAPI
ZwDeviceIoControlFile(
                      IN HANDLE FileHandle,
                      IN HANDLE Event OPTIONAL,
                      IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
                      IN PVOID ApcContext OPTIONAL,
                      OUT PIO_STATUS_BLOCK IoStatusBlock,
                      IN ULONG IoControlCode,
                      IN PVOID InputBuffer OPTIONAL,
                      IN ULONG InputBufferLength,
                      OUT PVOID OutputBuffer OPTIONAL,
                      IN ULONG OutputBufferLength
                      );

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryObject(
			  IN HANDLE ObjectHandle,
			  IN ULONG ObjectInformationClass,
			  OUT PVOID ObjectInformation,
			  IN ULONG ObjectInformationLength,
			  OUT PULONG ReturnLength OPTIONAL
			  );

NTSYSAPI
BOOLEAN
NTAPI
ZwDuplicateObject(
				  IN HANDLE hSourceProcessHandle,
				  IN HANDLE hSourceHandle,
				  IN HANDLE hTargetProcessHandle,
				  OUT HANDLE * lpTargetHandle,
				  IN ULONG dwDesiredAccess,
				  IN BOOLEAN bInheritHandle,
				  IN ULONG dwOptions
				  );
NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
						   IN ULONG ulProcId, 
						   OUT PEPROCESS * pEProcess
						   );


NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
						 IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
						 IN OUT PVOID SystemInformation,
						 IN ULONG SystemInformationLength,
						 OUT PULONG ReturnLength OPTIONAL
);

NTSTATUS WaitForUserAnswer();
PVOID GetUndocumentFunctionAdress()
{
	ULONG size,index;
	PULONG buf;
	ULONG i;
	PSYSTEM_MODULE_INFORMATION module;
	PVOID driverAddress=0;
	ULONG ntosknlBase;
	ULONG ntosknlEndAddr;
	ULONG curAddr;
	NTSTATUS status;
	PVOID retAddr;
	ULONG code1_sp2=0x8b55ff8b,code2_sp2=0x0cec83ec,code3_sp2=0xfff84d83,code4_sp2=0x7d8b5756;
	
	ZwQuerySystemInformation(SystemModuleInformation,&size, 0, &size);
	if(NULL==(buf = (PULONG)ExAllocatePool(PagedPool, size)))
	{
		DbgPrint("failed alloc memory failed \n");
		return 0;
	}
	status=ZwQuerySystemInformation(SystemModuleInformation,buf, size , 0);
	if(!NT_SUCCESS( status ))
	{
		DbgPrint("failed query\n");
		return 0;
	}
	module = (PSYSTEM_MODULE_INFORMATION)(( PULONG )buf + 1);
	ntosknlEndAddr=(ULONG)module->Base+(ULONG)module->Size;
	ntosknlBase=(ULONG)module->Base;
	curAddr=ntosknlBase;
	ExFreePool(buf);
	for (i=curAddr;i<=ntosknlEndAddr;i++)
	{
		if ((*((ULONG *)i)==code1_sp2)&&(*((ULONG *)(i+4))==code2_sp2)&&(*((ULONG *)(i+8))==code3_sp2)&&(*((ULONG*)(i+12))==code4_sp2)) 
		{
			retAddr=(PVOID*)i;
			DbgPrint("MyPspTerminateThreadByPointer  adress is:%x\n",retAddr); 
			return retAddr;
		}
	}
	DbgPrint("Can't Find MyPspTerminateThreadByPointer  Address:%x\n"); 
	return 0;
}






//载自ReactOS-0.3.4-REL-src
PETHREAD
NTAPI
GetNextProcessThread(IN PEPROCESS Process,
					 IN PETHREAD Thread OPTIONAL)
{
    PETHREAD FoundThread = NULL;
    PLIST_ENTRY ListHead, Entry;
    PAGED_CODE();
    
    if (Thread)
    {
		//  Entry = Thread->ThreadListEntry.Flink;;//   +0x22c ThreadListEntry  : _LIST_ENTRY
		Entry = (PLIST_ENTRY)((ULONG)(Thread)+0x224);
		Entry=Entry->Flink;
    }
    else
    {
        Entry = (PLIST_ENTRY)((ULONG)(Process)+0x180);//+0x190 ThreadListHead   : _LIST_ENTRY
        Entry = Entry->Flink; 
    }
	// ListHead = &Process->ThreadListHead;
	ListHead = (PLIST_ENTRY)((ULONG)Process + 0x180);
    while (ListHead != Entry)
    {
		//   FoundThread = CONTAINING_RECORD(Entry, ETHREAD, ThreadListEntry);
		FoundThread = (PETHREAD)((ULONG)Entry - 0x224);
		//    if (ObReferenceObjectSafe(FoundThread)) break;
		if (ObReferenceObject(FoundThread)) break;
        FoundThread = NULL;
        Entry = Entry->Flink;
    }
    if (Thread) ObDereferenceObject(Thread);
    return FoundThread;
}
NTSTATUS TerminateProcess( PEPROCESS Process )
{
	NTSTATUS          Status;
	PETHREAD          Thread;
	
	Status = STATUS_SUCCESS;
	__try
	{
		for (Thread = GetNextProcessThread( Process, NULL );
		Thread != NULL;
		Thread = GetNextProcessThread( Process, Thread ))
		{
			Status = STATUS_SUCCESS;
			Status = (*MyPspTerminateThreadByPointer)( Thread, 0);
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		Status = GetExceptionCode();
	}
	return Status;
}


VOID 
FreeLog(
			  VOID
			  )
{
	PLOG_BUF      next;

	//
	// Just traverse the list of allocated output buffers
	//
	while( Log ) {
		next = Log->Next;
		ExFreePool( Log );
		Log = next;
	}
}       
//----------------------------------------------------------------------
//
// RegmonNewLog
//
// Called when the current buffer has filled up. This moves us to the
// pre-allocated buffer and then allocates another buffer.
//
//----------------------------------------------------------------------
VOID 
NewLog( 
			 VOID 
			 )
{
	PLOG_BUF prev = Log, newLog; 
	if( MaxLog == NumLog ) {

		Log->Length = 0;
		return; 
	}
	if( !Log->Length ) {

		return;
	}

	newLog = ExAllocatePool( PagedPool, sizeof(*Log) );
	if( newLog ) { 

		RtlZeroMemory(newLog,sizeof(LOG_BUF));
		Log   = newLog;
		Log->Length  = 0;
		Log->Next = prev; //把Next指针指向先前的那个LOG
		NumLog++;

	} else {

		Log->Length = 0;
	}
}
//找出那个最老的LOG，用于向用户程序输出数据
//----------------------------------------------------------------------
PLOG_BUF 
OldestLog( 
				VOID 
				)
{
	PLOG_BUF  ptr = Log, prev = NULL;

	while( ptr->Next ) {

		ptr = (prev = ptr)->Next;
	}
	if( prev ) {

		prev->Next = NULL;    
		NumLog--;
	}
	return ptr;
}
//当用户程序不读数据时，重新设置LOG
//----------------------------------------------------------------------
VOID
ResetLog(
			   VOID
			   )
{
	PLOG_BUF  current, next;

	MUTEX_P( LogMutex );

	//
	// Traverse the list of output buffers
	//
	current = Log->Next;
	while( current ) {

		//
		// Free the buffer
		//
		next = current->Next;
		ExFreePool( current );
		current = next;
	}

	// 
	// Move the output pointer in the buffer that's being kept
	// the start of the buffer.
	// 
	NumLog = 1;
	Log->Length = 0;
	Log->Next = NULL;

	MUTEX_V( LogMutex );
}
//把程序行为放到LOG里
VOID
UpdateLog(PTSTR  pData)
{
	PMESSAGE  pTempM;
    ULONG      TempLength = 0;
	MUTEX_P(LogMutex);
	if(Log->Length > MAX_MESSAGE - 500)
	{
		NewLog();
	}
	//
	/*typedef struct _log
	{
	    ULONG              Length;
        struct _log * Next;
	     TCHAR              Message[MAX_MESSAGE];	
	}LOG_BUF,*PLOG_BUF;

	typedef struct
   {
	  ULONG  Sequence;
	  TCHAR  Message[0];
    }MESSAGE,*PMESSAGE;*/
	
	
	pTempM = (PMESSAGE)(Log->Message + Log->Length);//Log->Message+Log->Length后指针指向之前存的字符串的末尾
	//然后再装入数据知道指定长度
	if(pTempM == NULL)
	{
		DbgPrint("pTempM == NULL\n");
	}
	else
	{
		TempLength = sprintf(pTempM->Message,"%s",pData);
        Log->Length +=TempLength + 1;
		
	}
	MUTEX_V(LogMutex);
	return ;
}
void SafeObDereferenceObject(PVOID pObject)
{
	if(pObject)
	{
		ObDereferenceObject(pObject);
		pObject=NULL;
	}
}
///////////////////////////////////////////////////////////////////////////////////
//
//	功能实现：根据设备名获取文件句柄或文件对象指针
//	输入参数：FileHandle是要输出的文件句柄指针;
//			  FileObject是要输出的文件对象指针
//			  DeviceName是要获取设备的设备名
//	输出参数：返回NTSTATUS类型的值
//
///////////////////////////////////////////////////////////////////////////////////
NTSTATUS	
GetObjectByName(OUT HANDLE *FileHandle,OUT PFILE_OBJECT	*FileObject,IN WCHAR	*DeviceName)
{
	UNICODE_STRING		deviceTCPUnicodeString;
	OBJECT_ATTRIBUTES	TCP_object_attr;
	NTSTATUS			status;
	IO_STATUS_BLOCK		IoStatus;
	
	ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
	RtlInitUnicodeString(&deviceTCPUnicodeString,DeviceName);
	InitializeObjectAttributes(&TCP_object_attr,
		&deviceTCPUnicodeString,
		OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,
		0,
		0);
	status=ZwCreateFile(FileHandle,
		GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE,
		&TCP_object_attr,
		&IoStatus,
		0,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		0,
		0,
		0);
	if(!NT_SUCCESS(status))
	{
		KdPrint(("Failed to open"));
		return STATUS_UNSUCCESSFUL;
	}
	status=ObReferenceObjectByHandle(*FileHandle,
		FILE_ANY_ACCESS,
		0,
		KernelMode,
		(PVOID*)FileObject,
		NULL);
	
	return status;
}

///////////////////////////////////////////////////////////////////////////////////
//
//	功能实现：枚举网络连接端口信息
//	输入参数：OutLength为输出缓冲区的大小
//			  PortType为要枚举的端口类型
//				TCPPORT-TCP端口
//				UDPPORT-UDP端口
//	输出参数：返回NTSTATUS类型的值
//
///////////////////////////////////////////////////////////////////////////////////
PVOID		
EnumPortInformation(OUT PULONG	OutLength,IN USHORT	PortType)
{
	ULONG	BufLen=PAGE_SIZE;
	PVOID	pInputBuff=NULL;
	PVOID	pOutputBuff=NULL;
	PVOID	pOutBuf=NULL;
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE FileHandle=NULL;
	UNICODE_STRING	DeviceName;
	PFILE_OBJECT pFileObject=NULL;
	PDEVICE_OBJECT pDeviceObject=NULL;
	KEVENT	Event ;
	IO_STATUS_BLOCK StatusBlock;
	PIRP		pIrp;
	PIO_STACK_LOCATION StackLocation ;
	ULONG		NumOutputBuffers;
	ULONG		i;
	TCP_REQUEST_QUERY_INFORMATION_EX		TdiId;

	RtlZeroMemory(&TdiId,sizeof(TCP_REQUEST_QUERY_INFORMATION_EX));

	if(TCPPORT==PortType)
	{
		TdiId.ID.toi_entity.tei_entity= CO_TL_ENTITY;
	}

	if(UDPPORT==PortType)
	{
		TdiId.ID.toi_entity.tei_entity= CL_TL_ENTITY;
	}

	TdiId.ID.toi_entity.tei_instance = ENTITY_LIST_ID;
	TdiId.ID.toi_class = INFO_CLASS_PROTOCOL;
	TdiId.ID.toi_type = INFO_TYPE_PROVIDER;
	TdiId.ID.toi_id = 0x102;

	pInputBuff=(PVOID)&TdiId;

	__try
	{
		if(UDPPORT==PortType)
		{
			BufLen*=3;
		}
		pOutputBuff=ExAllocatePool(NonPagedPool, BufLen);
		if(NULL==pOutputBuff)
		{
			KdPrint(("输出缓冲区内存分配失败！\n"));
			*OutLength=0;
			__leave;
		}

		if(TCPPORT==PortType)
		{
			status = GetObjectByName(&FileHandle, &pFileObject,L"\\Device\\Tcp");
		}
		
		if(UDPPORT==PortType)
		{
			status = GetObjectByName(&FileHandle, &pFileObject, L"\\Device\\Udp");
		}
		if (!NT_SUCCESS(status))
		{
			KdPrint(("获取设备名失败！\n"));
			*OutLength=0;
			__leave;
		}

		pDeviceObject = IoGetRelatedDeviceObject(pFileObject);
		if (NULL == pDeviceObject)
		{
			KdPrint(("获取设备对象失败！\n"));
			*OutLength=0;
			__leave;
		}

		KdPrint(("Tcpip Driver Object:%08lX\n", pDeviceObject->DriverObject));
		KeInitializeEvent(&Event, 0, FALSE);
		
		pIrp = IoBuildDeviceIoControlRequest(IOCTL_TCP_QUERY_INFORMATION_EX, \
								pDeviceObject, pInputBuff, sizeof(TCP_REQUEST_QUERY_INFORMATION_EX), \
								pOutputBuff,BufLen, FALSE, &Event, &StatusBlock);
		if (NULL == pIrp)
		{
			KdPrint(("IRP生成失败！\n"));
			*OutLength=0;
			__leave;
		}

		StackLocation = IoGetNextIrpStackLocation(pIrp);
		StackLocation->FileObject = pFileObject;//不设置这里会蓝屏
		StackLocation->DeviceObject = pDeviceObject;

		status  = IoCallDriver(pDeviceObject, pIrp);
		
		KdPrint(("STATUS:%08lX\n", status));
		
		if (STATUS_BUFFER_OVERFLOW == status)
		{
			KdPrint(("缓冲区太小！%d\n",StatusBlock.Information));
		}

		if (STATUS_PENDING == status)
		{
			KdPrint(("STATUS_PENDING"));
			status = KeWaitForSingleObject(&Event, 0, 0, 0, 0);
		}

		if(STATUS_CANCELLED==status)
		{
			KdPrint(("STATUS_CANCELLED"));
		}
		
		if(status==STATUS_SUCCESS)
		{
			*OutLength=StatusBlock.Information;
			pOutBuf=pOutputBuff;
		}
	}
	__finally
	{ 
		SafeObDereferenceObject(pFileObject); 
		if(FileHandle)
		{
			ZwClose(FileHandle);
		}
	}
	return pOutBuf;
}
////////////////////////////////////////////////////////
ULONG  GetPebAddress()
{
  ULONG Address;
  PEPROCESS pEProcess;

        //由于system进程的peb总是零 我们只有到其他进程去找了
  pEProcess = (PEPROCESS)((ULONG)((PLIST_ENTRY)((ULONG)pSystem + PROCESS_LINK_OFFSET))->Flink - PROCESS_LINK_OFFSET);
  Address   = *(PULONG)((ULONG)pEProcess + PEB_OFFSET);

  return (Address & 0xFFFF0000);  
}
///////////////////////////////////////////////////////
VOID EnumProcess()
{
  ULONG  uSystemAddress = (ULONG)pSystem;
  ULONG  i;
  ULONG  Address;
  ULONG  ret;

  DbgPrint("-------------------------------------------");
  DbgPrint("EProcess    PID    ImageFileName");
  DbgPrint("---------------------------------");
  
  
  for(i = 0x80000000; i < uSystemAddress; i += 4){//system进程的EPROCESS地址就是最大值了
    ret = VALIDpage(i); 
    if (ret == VALID){ 
      Address = *(PULONG)i;
      if (( Address & 0xFFFF0000) == pebAddress){//每个进程的PEB地址都是在差不多的地方，地址前半部分是相同的       
        if(IsaRealProcess(i)){ 
          ShowProcess(i - PEB_OFFSET);  
           i += EPROCESS_SIZE;                
        } 
      } 
    }else if(ret == PTE_INVALID){ 
      i -=4; 
      i += 0x1000;//4k 
    }else{ 
      i-=4; 
      i+= 0x400000;//4mb 
    } 
  }

  ShowProcess(uSystemAddress);//system的PEB总是零 上面的方法是枚举不到的 不过我们用PsGetCurrentProcess就能得到了
  DbgPrint("-------------------------------------------");
  
}
/////////////////////////////////////////////////////////
VOID    ShowProcess(ULONG pEProcess)
{
  PLARGE_INTEGER ExitTime;
  ULONG PID;
  PUCHAR pFileName;
  TCHAR     pMessage[256];
  
  ExitTime = (PLARGE_INTEGER)(pEProcess + EXIT_TIME_OFFSET);  
  if(ExitTime->QuadPart != 0) //已经结束的进程的ExitTime为非零
    return ;

  PID = *(PULONG)(pEProcess + PROCESS_ID_OFFSET);
  pFileName = (PUCHAR)(pEProcess + FILE_NAME_OFFSET);

  DbgPrint("0x%08X  %04d   %s",pEProcess,PID,pFileName);
  sprintf(pMessage,"%d\t%s\t%0x", PID,pFileName,pEProcess);
  UpdateLog((PTSTR)pMessage);
}
ULONG   VALIDpage(ULONG addr)
{
// 	ULONG PDE,PTE;
// 	BYTE PresentSign = 0x1;
// 	BYTE PageSizeSign = 0x80;
// 	BYTE PresentAndPageSizeSign = 0x81;
// 	ULONG  PdeContext,PteContext;

	if (!MmIsAddressValid((PVOID)addr))
	{
		return PTE_INVALID;
	}
	else 
	{
		return VALID;
	}
}
////////////////////////////////////////////////////////////////
BOOLEAN IsaRealProcess(ULONG i) 
{ 
  NTSTATUS STATUS; 
  PUNICODE_STRING pUnicode; 
  UNICODE_STRING Process; 
  ULONG pObjectType; 
  ULONG ObjectTypeAddress; 
  
  if (VALIDpage(i- PEB_OFFSET) != VALID){ 
    return FALSE; 
  } 

  ObjectTypeAddress = i - PEB_OFFSET - OBJECT_HEADER_SIZE + OBJECT_TYPE_OFFSET ;
  
  if (VALIDpage(ObjectTypeAddress) == VALID){ 
    pObjectType = *(PULONG)ObjectTypeAddress; 
  }else{ 
    return FALSE; 
  } 
  
  if(pObjectTypeProcess == pObjectType){ //确定ObjectType是Process类型
    return TRUE; 
  } 
  return FALSE; 

} 
void GetProcessNameOffset()
{
    
    PEPROCESS curproc;
    int i;
    curproc = PsGetCurrentProcess();
    for( i = 0; i < 3*PAGE_SIZE; i++ )
    {
        if( !strncmp( "System", (PCHAR) curproc + i, strlen("System") ))
        {
            gProcessNameOffset = i;
        }
    }
}

BOOLEAN GetProcessName( PCHAR theName )
{
    PEPROCESS       curproc;
    char            *nameptr;
    ULONG           i;
   
    if( gProcessNameOffset )
    {
        curproc = PsGetCurrentProcess();
        nameptr   = (PCHAR) curproc + gProcessNameOffset;
        strncpy( theName, nameptr, NT_PROCNAMELEN );
        theName[NT_PROCNAMELEN] = 0; /* NULL at end */
        return TRUE;
    }
    return FALSE;
}
BOOLEAN GetRegistryObjectCompleteName(PUNICODE_STRING pRegistryPath, PUNICODE_STRING pPartialRegistryPath, PVOID pRegistryObject)
{
     BOOLEAN foundCompleteName = FALSE;
     BOOLEAN partial = FALSE;
     if((!MmIsAddressValid(pRegistryObject)) ||
     (pRegistryObject == NULL))
	 {
      return FALSE;
	 }
      /* Check to see if the partial name is really the complete name */
     if(pPartialRegistryPath != NULL)
	 {
        if((((pPartialRegistryPath->Buffer[0] == '\\') || (pPartialRegistryPath->Buffer[0] == '%')) ||
         ((pPartialRegistryPath->Buffer[0] == 'T') && (pPartialRegistryPath->Buffer[1] == 'R') && (pPartialRegistryPath->Buffer[2] == 'Y') && (pPartialRegistryPath->Buffer[3] == '\\'))) )
		{
           RtlUnicodeStringCopy(pRegistryPath, pPartialRegistryPath);
           partial = TRUE;
           foundCompleteName = TRUE;
		}
	 }

     if(!foundCompleteName)
	 {
         /* Query the object manager in the kernel for the complete name */
        NTSTATUS status;
       ULONG returnedLength;
       PUNICODE_STRING pObjectName = NULL;

       status = ObQueryNameString(pRegistryObject, (POBJECT_NAME_INFORMATION)pObjectName, 0, &returnedLength );
       if(status == STATUS_INFO_LENGTH_MISMATCH)
	   {
         pObjectName = ExAllocatePoolWithTag(NonPagedPool, returnedLength, REGISTRY_POOL_TAG); 
         status = ObQueryNameString(pRegistryObject, (POBJECT_NAME_INFORMATION)pObjectName, returnedLength, &returnedLength );
         if(NT_SUCCESS(status))
		 {
            RtlUnicodeStringCopy(pRegistryPath, pObjectName);
            foundCompleteName = TRUE;
		 }
          ExFreePoolWithTag(pObjectName, REGISTRY_POOL_TAG);
	   }
	 }
      //ASSERT(foundCompleteName == TRUE);
      return foundCompleteName;
}
NTSTATUS RegistryCallback(IN PVOID CallbackContext, 
IN PVOID Argument1, 
IN PVOID Argument2)
{  
	NTSTATUS st=STATUS_SUCCESS;
    BOOLEAN exception = FALSE;  
	BOOLEAN flag;
    int type;
    UNICODE_STRING registryPath;
    UCHAR* registryData = NULL;
    ULONG registryDataLength = 0;
    ULONG registryDataType = 0;
    /* Allocate a large 64kb string ... maximum path name allowed in windows */
    registryPath.Length = 0;
    registryPath.MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
    registryPath.Buffer = ExAllocatePoolWithTag(NonPagedPool, registryPath.MaximumLength, REGISTRY_POOL_TAG); 
    if(registryPath.Buffer == NULL)
	{
     return STATUS_SUCCESS;
	}

    //registryEvent.eventType = (REG_NOTIFY_CLASS)Argument1;
    type = (REG_NOTIFY_CLASS)Argument1;
    try
	{
       /* Large switch statement for all registry events ... fairly easy to understand */
       switch(type)
	   {
		  case RegNtPreDeleteKey:
		{
			PREG_DELETE_KEY_INFORMATION deleteKey = (PREG_DELETE_KEY_INFORMATION)Argument2;
			PCM_KEY_BODY my_CM_KEY_BODY=(PCM_KEY_BODY)deleteKey->Object;
		   GetProcessName(aProcessName);
			flag=GetRegistryObjectCompleteName(&registryPath, NULL, deleteKey->Object);
			if(flag) 
			{
				RtlUnicodeStringToAnsiString(&astr,&registryPath,TRUE);
				DbgPrint("[RegCreated]ProcessID %d KeyName %s!\n",PID,astr.Buffer);
				st=WaitForUserAnswer();
				if (!NT_SUCCESS(st))
					return STATUS_INVALID_PARAMETER;
				RtlFreeAnsiString(&astr);
			}
		    break;		 
		}
		  case RegNtPreDeleteValueKey:
		{
			
			PREG_DELETE_VALUE_KEY_INFORMATION deleteValueKey = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
			PCM_KEY_BODY my_CM_KEY_BODY=(PCM_KEY_BODY)deleteValueKey->Object;
			GetProcessName(aProcessName);
			flag=GetRegistryObjectCompleteName(&registryPath, NULL, deleteValueKey->Object);
			if((flag) && (deleteValueKey->ValueName->Length > 0)) 
			{
				RtlUnicodeStringCatString(&registryPath,L"\\");
				RtlUnicodeStringCat(&registryPath, deleteValueKey->ValueName);
				RtlUnicodeStringToAnsiString(&astr,&registryPath,TRUE);
				DbgPrint("[RegCreated]ProcessID %d KeyName %s!\n",PID,astr.Buffer);
				st=WaitForUserAnswer();
				if (!NT_SUCCESS(st))
				       return STATUS_INVALID_PARAMETER;
				RtlFreeAnsiString(&astr);
			}
				  break;
		}
		  case RegNtPreSetValueKey:
		{
			PREG_SET_VALUE_KEY_INFORMATION setValueKey = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
			PCM_KEY_BODY my_CM_KEY_BODY=(PCM_KEY_BODY)setValueKey->Object;
		    GetProcessName(aProcessName);
			flag = GetRegistryObjectCompleteName(&registryPath, NULL, setValueKey->Object);
			if((flag) && (setValueKey->ValueName->Length > 0)) 
			{
				registryDataType = setValueKey->Type;
				registryDataLength = setValueKey->DataSize;
				registryData = ExAllocatePoolWithTag(NonPagedPool, registryDataLength, REGISTRY_POOL_TAG);
				if(registryData != NULL)
				{
					RtlCopyBytes(registryData,setValueKey->Data,setValueKey->DataSize);
				} else {
					DbgPrint("RegistryMonitor: ERROR can't allocate memory for setvalue data\n");
				}
				RtlUnicodeStringCatString(&registryPath,L"\\");
				RtlUnicodeStringCat(&registryPath, setValueKey->ValueName);
				RtlUnicodeStringToAnsiString(&astr,&registryPath,TRUE);
				DbgPrint("[RegCreated]ProcessID %d KeyName %s!\n",PID,astr.Buffer);
				  if (strstr(astr.Buffer,"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"))
				  {
					   st=WaitForUserAnswer();
				       if (!NT_SUCCESS(st))
				            return STATUS_INVALID_PARAMETER;
				  }
				  else if (strstr(astr.Buffer,"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices"))
				  {
                      st=WaitForUserAnswer();
					  if (!NT_SUCCESS(st))
				           return STATUS_INVALID_PARAMETER;
				  }
				  else if (strstr(astr.Buffer," \\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"))
				  {
					  st=WaitForUserAnswer();
					  if (!NT_SUCCESS(st))
				            return STATUS_INVALID_PARAMETER;
				  }
				  else if (strstr(astr.Buffer,"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"))
				  {
					  st=WaitForUserAnswer();
					  if (!NT_SUCCESS(st))
				            return STATUS_INVALID_PARAMETER;
				  }
				  else if (strstr(astr.Buffer,"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"))
				  {
					  st=WaitForUserAnswer();
					  if (!NT_SUCCESS(st))
				            return STATUS_INVALID_PARAMETER;
				  }
				  else if (strstr(astr.Buffer," \\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"))
				  {
					  st=WaitForUserAnswer();
					  if (!NT_SUCCESS(st))
				            return STATUS_INVALID_PARAMETER;
				  }
                  else if (strstr(astr.Buffer,"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"))
				  {
					  st=WaitForUserAnswer();
					  if (!NT_SUCCESS(st))
				            return STATUS_INVALID_PARAMETER;
				  }
				   RtlFreeAnsiString(&astr);
			}
				  break;		 
		}
	    
		  default:
			  break;
	   }
	   } except( EXCEPTION_EXECUTE_HANDLER ) {
		   /* Do nothing if an exception occured ... event won't be queued */
		   exception = TRUE;
	   }
	  
	   if(registryPath.Buffer != NULL)
	   {
		   ExFreePoolWithTag(registryPath.Buffer, REGISTRY_POOL_TAG);
	   }
       /* Always return a success ... we aren't doing any filtering, just monitoring */
       return STATUS_SUCCESS;
}
NTSTATUS WaitForUserAnswer()
{
	if (EventKernelWait && EventKernelSet)
	{
		if (CreateIsProgressing) return STATUS_ACCESS_DENIED; // 防止混乱
		CreateIsProgressing=TRUE;
		KeSetEvent(EventKernelSet,0,FALSE);
		KeWaitForSingleObject(EventKernelWait,Executive,KernelMode,FALSE,NULL);
		KeResetEvent(EventKernelSet);
		CreateIsProgressing=FALSE;
		return (CreateAllowed?STATUS_SUCCESS:STATUS_ACCESS_DENIED);
	}
	return STATUS_SUCCESS;
}	
NTSTATUS SSDTDeviceIoCtl( PDEVICE_OBJECT pDeviceObject, PIRP Irp )
{
//	ULONG pbuf;
	PLOG_BUF    old;
	NTSTATUS s;
	PIO_STACK_LOCATION IrpStack;
	PVOID InputBuffer;
	PVOID OutputBuffer;
	ULONG InputBufferLength;
	ULONG OutputBufferLength;
	ULONG IoControlCode;
		
	s = Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	
	IrpStack = IoGetCurrentIrpStackLocation( Irp );
	
	InputBuffer = IrpStack->Parameters.DeviceIoControl.Type3InputBuffer;
	InputBufferLength = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
	OutputBuffer = Irp->UserBuffer;
	OutputBufferLength = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	IoControlCode = IrpStack->Parameters.DeviceIoControl.IoControlCode;
	
	///////////////////////////////////////////////
	//这里处理分发例程
	switch( IoControlCode )
	{
	case IOCTL_REG_PROTECTION://开启注册表保护
		CmRegisterCallback(RegistryCallback,
			NULL,
			&Cookie
		);
		Prot=TRUE;
		break;
	case IOCTL_STOP_PROTECTION://停止注册表保护
        CmUnRegisterCallback(Cookie);
		Prot=FALSE;
		break;
	case IOCTL_SAVE_EVENT://把事件传到驱动
		{
			EVENT_INFORMATION EvntInfo;
			__try
			{   
				ProbeForRead( InputBuffer, sizeof(EvntInfo), sizeof( ULONG ) );
				memcpy(&EvntInfo,InputBuffer,8);
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				;
			}
			if (!NT_SUCCESS(ObReferenceObjectByHandle(EvntInfo.hKernelSetEvent,0,*ExEventObjectType,UserMode,&EventKernelSet,NULL)))
			{
				EventKernelSet=NULL;
			}
			if (!NT_SUCCESS(ObReferenceObjectByHandle(EvntInfo.hKernelWaitEvent,0,*ExEventObjectType,UserMode,&EventKernelWait,NULL)))
			{
				EventKernelWait=NULL;
			}
			DbgPrint("[Kernel_Driver] EventKernelSet = 0x%X, EventKernelWait=0x%X.\n",EventKernelSet,EventKernelWait);
			s = STATUS_SUCCESS;
			break;
		}
	case IOCTL_REGISTRY_INFO://获得注册表信息
		{
			DbgPrint("[Kernel_Driver] IOCTL_GET_CREATE_PROC_INFO.\n");
			__try
			{
				REGISTRY_INFORMATION RegInfo={0};
				memcpy(RegInfo.ProcessName,aProcessName,256);
				memcpy(RegInfo.KeyPath,astr.Buffer,256);
				DbgPrint("%s %s.\n",RegInfo.ProcessName,RegInfo.KeyPath);
				ProbeForWrite( OutputBuffer, sizeof(RegInfo), sizeof( ULONG ) );
				RtlCopyMemory(OutputBuffer,&RegInfo,sizeof(RegInfo)); // it's strange.
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				DbgPrint("[Kernel_Driver] IOCTL_GET_CREATE_PROC_INFO raised exception.\n");
				;
			}
			break;
		}
	case IOCTL_ALLOW_MODIFY://允许修改
		{
			__try
			{   
				ProbeForRead( InputBuffer, sizeof(CreateAllowed), sizeof( ULONG ) );
				memcpy(&CreateAllowed,InputBuffer,sizeof(CreateAllowed));
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				;
			}
			break;
		}
	//*************************************************
	case IOCTL_GETSSDT:	//得到SSDT
		__try
		{
			ProbeForWrite( OutputBuffer, sizeof( MYSSDT ), sizeof( ULONG ) );
			RtlCopyMemory( OutputBuffer, KeServiceDescriptorTable, sizeof( MYSSDT ) );
		}
		__except( EXCEPTION_EXECUTE_HANDLER )
		{
			s = GetExceptionCode();
			break;
		}
		DbgPrint( "SSDT: GetSSDT Completeled!" );
		break;
	case IOCTL_KILL:
		{
			__try
			{
				ProbeForRead( InputBuffer, sizeof( ULONG ), sizeof( ULONG ) );
				memcpy(&processID,InputBuffer,sizeof(processID));
				s=PsLookupProcessByProcessId(processID,&eProcess);
				if(NT_SUCCESS(s))
				{
					ObDereferenceObject(eProcess);
				}
				s=TerminateProcess(eProcess);
				if(NT_SUCCESS(s))
				{
					DbgPrint("TerminateProcess Ok!\n");
				}
			}
			__except( EXCEPTION_EXECUTE_HANDLER )
			{
				s = GetExceptionCode();
				break;
			}
			//	status = STATUS_SUCCESS;
			break;
		}
	case IOCTL_ENUMTCP://枚举TCP连接
		{
			PVOID	pOut=NULL;
			ULONG	OutLen=0; 
			
			if(OutputBufferLength<sizeof(CONNINFO102))
			{
				KdPrint(("输出缓冲区长度无效\n"));
				s=STATUS_BUFFER_OVERFLOW;
				break;
			}
			
			pOut=EnumPortInformation(&OutLen,TCPPORT);
			if(!pOut)
			{
				KdPrint(("获取TCP端口信息失败!\n"));
				s=STATUS_UNSUCCESSFUL;
				break;
			}
			
			if(OutputBufferLength<OutLen)
			{
				KdPrint(("输出缓冲区太小,应为%ld\n",OutLen));
				ExFreePool(pOut);
				s=STATUS_BUFFER_OVERFLOW;
				break;
			} 
			
			RtlCopyMemory(OutputBuffer,pOut,OutLen);
			
			ExFreePool(pOut);
			Irp->IoStatus.Information = OutLen;
			break;
		}
	case IOCTL_ENUMUDP://枚举UDP连接
		{
			PVOID	pOut=NULL;
			ULONG	OutLen=0;  
			
			if(OutputBufferLength<sizeof(UDPCONNINFO))
			{
				KdPrint(("输出缓冲区长度无效\n"));
				s=STATUS_BUFFER_OVERFLOW;
				break;
			}
			
			pOut=EnumPortInformation(&OutLen,UDPPORT);
			if(!pOut)
			{
				KdPrint(("获取UDP端口信息失败!\n"));
				s=STATUS_UNSUCCESSFUL;
				break;
			}
			
			if(OutputBufferLength<OutLen)
			{
				KdPrint(("输出缓冲区太小,应为%ld\n",OutLen));
				ExFreePool(pOut);
				s=STATUS_BUFFER_OVERFLOW;
				break;
			}
			
			RtlCopyMemory(OutputBuffer,pOut,OutLen);
			
			ExFreePool(pOut);
			Irp->IoStatus.Information = OutLen;
            break;
		}
	case IOCTL_QSIADDR:
        EnumProcess();
		__try {                 
			
            ProbeForWrite( OutputBuffer,
				OutputBufferLength,
				sizeof( UCHAR ));
			
        } __except( EXCEPTION_EXECUTE_HANDLER ) {
			
            Irp->IoStatus.Information = STATUS_INVALID_PARAMETER;
            return FALSE;
        }            

		if(MAX_MESSAGE > OutputBufferLength)
		{
			return FALSE;
		}
		else 
			if(Log->Length != 0	||  Log->Next   != NULL)
			{
				//pReturnLog = Log;
				MUTEX_P(LogMutex);
				//	NewLog();
				old=OldestLog();
				if(old!=Log)
				{
					MUTEX_V(LogMutex);
					DbgPrint("Old log\n");
				}
				memcpy(OutputBuffer,old->Message,old->Length);
					Irp->IoStatus.Information = old->Length;
				if(old!=Log)
				{
					ExFreePool(old);
				}
				else
				{
					DbgPrint("Current log\n");
					Log->Length=0;
					MUTEX_V(LogMutex);
				}
			}
			else
			{   
				//	MUTEX_V(LogMutex);
					Irp->IoStatus.Information = 0;
			}
			
			

		DbgPrint("SSDT: Set QuerySystemInformation Address Completed!");
                break;
	case IOCTL_SETSSDT: //设置 SSDT
		__try
		{
			ProbeForRead( InputBuffer, sizeof( MYSSDT ), sizeof( ULONG ) );
			//去掉内存保护
			__asm
			{
				cli		;//关中断
				mov eax, cr0
				and eax, ~0x10000
				mov cr0, eax
			}
			RtlCopyMemory( KeServiceDescriptorTable, InputBuffer, sizeof( MYSSDT ) );
			//开中断,把内存保护加上
			 __asm
			 {
				mov eax, cr0
				or eax, 0x10000
				mov cr0, eax
				sti		;//开中断
			 }
		}
		__except( EXCEPTION_EXECUTE_HANDLER )
		{
			s = GetExceptionCode();
			break;
		}
		DbgPrint( "SSDT: SetSSDT Completeled!" );
		break;
	//*************************************************
	case IOCTL_GETHOOK:	//查询SSDT指定地址
		__try
		{
			ProbeForRead( InputBuffer, sizeof( ULONG ), sizeof( ULONG ) );
			ProbeForWrite( OutputBuffer, sizeof( ULONG ), sizeof( ULONG ) );
		}
		__except( EXCEPTION_EXECUTE_HANDLER )
		{
			s = GetExceptionCode();
			break;
		}
		//测试传入的参数是否正确
		if( KeServiceDescriptorTable->ulNumberOfServices <= *(PULONG)InputBuffer )
		{
			s = STATUS_INVALID_PARAMETER;
			break;
		}
		//将结果传到用户输出位置
		*((PULONG)OutputBuffer) = *( (PULONG)(KeServiceDescriptorTable->pvSSDTBase) + *(PULONG)InputBuffer );
		DbgPrint( "SSDT: GetHookedAddress Completeled!" );
		break;
	//*************************************************
	case IOCTL_SETHOOK:	//设置SSDT指定地址
		__try
		{
			ProbeForRead( InputBuffer, sizeof( ULONG ), sizeof( ULONG ) );
			ProbeForRead( OutputBuffer, sizeof( ULONG ), sizeof( ULONG ) );
		}
		__except( EXCEPTION_EXECUTE_HANDLER )
		{
			s = GetExceptionCode();
			break;
		}
		//测试传入的参数是否正确
		if( KeServiceDescriptorTable->ulNumberOfServices <= *(PULONG)InputBuffer )
		{
			s = STATUS_INVALID_PARAMETER;
			break;
		}
		//在此将输出缓冲区当作输入缓冲区来用,输入指定SSDT HOOK的地址值
		//去掉内存保护
		__asm
		{
			cli		;//关中断
			mov eax, cr0
			and eax, ~0x10000
			mov cr0, eax
		}
		 *( (PULONG)(KeServiceDescriptorTable->pvSSDTBase) + *(PULONG)InputBuffer ) = *((PULONG)OutputBuffer);
		 //开中断,把内存保护加上
		 __asm
		 {
			mov eax, cr0
			or eax, 0x10000
			mov cr0, eax
			sti		;//开中断
		 }
		 DbgPrint( "SSDT: SetHookedAddress Completeled!" );
		break;
	//*************************************************
	default:
		s = STATUS_INVALID_DEVICE_REQUEST;
		DbgPrint( "SSDT: Invalid Parameter Completeled!" );
		break;
	}
	///////////////////////////////////////////////
	
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	
	return s;
}

void SSDTUnload( PDRIVER_OBJECT pDriverObject )
{
	UNICODE_STRING	usDosDeviceName;
	if (Prot)
	    CmUnRegisterCallback(Cookie);
	if (EventKernelSet)
	{
		ObDereferenceObject(EventKernelSet);
		EventKernelSet=NULL;
	}
	if (EventKernelWait)
	{
		ObDereferenceObject(EventKernelWait);
		EventKernelWait=NULL;
	}
	RtlInitUnicodeString( &usDosDeviceName, DEVICE_NAME );
	IoDeleteSymbolicLink( &usDosDeviceName );
	IoDeleteDevice( pDriverObject->DeviceObject );
	FreeLog();
	
	DbgPrint( "SSDT: Unload Success!" );
}

NTSTATUS SSDTCreate( IN PDEVICE_OBJECT pDeviceObject, IN PIRP Irp )
{
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	DbgPrint( "SSDT: Create Success!" );
	return STATUS_SUCCESS;
}
NTSTATUS SSDTClose( IN PDEVICE_OBJECT pDeviceObject, IN PIRP Irp )
{
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	ResetLog();
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	DbgPrint( "SSDT: Create Success!" );
	return STATUS_SUCCESS;
}
NTSTATUS DriverEntry(	PDRIVER_OBJECT pDriverObject,
						PUNICODE_STRING pRegistryPath )
{
	PDEVICE_OBJECT pdo = NULL;
	NTSTATUS s = STATUS_SUCCESS;
	UNICODE_STRING usDriverName, usDosDeviceName;
        
	
	RtlInitUnicodeString( &usDriverName, DRIVER_NAME );
	RtlInitUnicodeString( &usDosDeviceName, DEVICE_NAME );
	
	s = IoCreateDevice( pDriverObject, 0, &usDriverName, \
		FILE_DRIVER_SSDT, FILE_DEVICE_SECURE_OPEN, \
		FALSE, &pdo );
	
	if( STATUS_SUCCESS == s )
	{
		pDriverObject->MajorFunction[IRP_MJ_CREATE] = SSDTCreate;
		pDriverObject->MajorFunction[IRP_MJ_CLOSE]=SSDTClose;
		pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] \
			= SSDTDeviceIoCtl;
		pDriverObject->DriverUnload = SSDTUnload;
		
		IoCreateSymbolicLink( &usDosDeviceName, &usDriverName );
	}
	MUTEX_INIT(LogMutex);
	//	GetProcessNameOffset();
	
	Log = ExAllocatePool(NonPagedPool,sizeof(LOG_BUF));
	if(Log == NULL)
	{
	   s = STATUS_INSUFFICIENT_RESOURCES;
	}
	else
	{
		Log->Length = 0;
		Log->Next   = NULL;
		//pCurrentLog       = Log;
		NumLog      = 1;
	}
	
        pSystem    = PsGetCurrentProcess();
       DbgPrint("pSystem %0x",pSystem);
      pebAddress = GetPebAddress();
      pObjectTypeProcess = *(PULONG)((ULONG)pSystem - OBJECT_HEADER_SIZE +OBJECT_TYPE_OFFSET);  

	
	MyPspTerminateThreadByPointer  =GetUndocumentFunctionAdress();
	GetProcessNameOffset();

	DbgPrint( "SSDT: Load Success!" );
	
	return s;
}