
#include <ntddk.h>
#include <windef.h>
#include <string.h>


ULONG g_uCr0;


BYTE g_OrigNtOpenProcess[6] = { 0 }; // 原函数的前字节内容
BYTE g_OrigNtOpenThread[6] = { 0 }; // 原函数的前字节内容


ULONG uOriginObOpenObjectByPointerAddr;

ULONG uOriginNtOpenProcessAddr;
ULONG uMyHookedNtOpenProcessAddr;
ULONG uTPHookedNtOpenProcessJmpAddr;
ULONG uMyHookedNtOpenProcessJmpAddr;

ULONG uOriginNtOpenThreadAddr;
ULONG uMyHookedNtOpenThreadAddr;
ULONG uTPHookedNtOpenThreadJmpAddr;
ULONG uMyHookedNtOpenThreadJmpAddr;


void WPOFF()
{
    ULONG uAttr;
    _asm
    {
        push eax;
        mov eax, cr0;
        mov uAttr, eax;
        and eax, 0FFFEFFFFh; // CR0 16 BIT = 0
        mov cr0, eax;
        pop eax;
        cli
    };

    g_uCr0 = uAttr; //保存原有的 CRO 屬性

}

VOID WPON()
{

    _asm
    {
        sti
            push eax;
        mov eax, g_uCr0; //恢復原有 CR0 屬性
        mov cr0, eax;
        pop eax;
    };

}



/* 
HookAddr				Hook安装地址 
NewFunctionAddr         新函数地址 
CopyBuffer              存储原始数据的Buff
BufferLength            复制缓冲区的长度
*/  
VOID InstallInLineHook(  
                ULONG HookAddr,  
                ULONG NewFunctionAddr,   
                ULONG CopyBuffer,   
                ULONG BufferLength)
{
	KIRQL  oldIrql;
	
	ULONG JmpAddr = 0;
    
    // 保存原函数的前字节内容
    RtlCopyMemory((BYTE*)CopyBuffer, (BYTE*)HookAddr, BufferLength);
   

    // 禁止系统写保护，提升IRQL到DPC
    WPOFF();
    oldIrql = KeRaiseIrqlToDpcLevel();

    *(BYTE*)(HookAddr) =0xE9;
	//jmp指令，此处为短跳，计算相对偏移，同时，jmp xxxxxx这条指令占了5个字节
	JmpAddr = NewFunctionAddr - (HookAddr + 5);
    *( (ULONG*)(HookAddr +1)) = JmpAddr;

    // 恢复写保护，降低IRQL
    KeLowerIrql(oldIrql);
    WPON();
	
}				

/* 
HookAddr			    Hook安装位置 
CopyBuffer              存储原始数据的Buff
BufferLen            	复制缓冲区的长度
*/  
BOOL UnInstallInLineHook(  
                ULONG HookAddr,  
                ULONG OrgBuffer,   
                ULONG BufferLen)
{
	KIRQL  oldIrql;
	
    // 禁止系统写保护，提升IRQL到DPC
    WPOFF();
    oldIrql = KeRaiseIrqlToDpcLevel();

	RtlZeroMemory((BYTE*)HookAddr, 0xCC, BufferLen);

    // 保存原函数的前字节内容
    RtlCopyMemory((BYTE*)HookAddr, (BYTE*)OrgBuffer, BufferLen);

    // 恢复写保护，降低IRQL
    KeLowerIrql(oldIrql);
    WPON();
	
}					
				
//通过函数名获取在内核中的位置。
//FunctionName:函数名称			
ULONG GetFunctionAddr( IN PCWSTR FunctionName)
{
    UNICODE_STRING UniCodeFunctionName;
    RtlInitUnicodeString( &UniCodeFunctionName, FunctionName );
    return (ULONG)MmGetSystemRoutineAddress( &UniCodeFunctionName );  
}
				
				
//根据特征值，从原函数开始位置开始搜索特征码的位置。
//uOriginAddr:原函数的开始地址
//Findcode：特征码
//uLen：特征码长度
//szFunc：搜索内存长度
ULONG SearchFeature(char *uOriginAddr, char *Findcode, UINT uLen,UINT szFunc)
{

    int i = 0;

    ULONG Addr_Hook = 0;
   
    for(i = 0; i < (szFunc-uLen) ; i ++)
    {
	
		if( RtlEqualMemory(uOriginAddr+i,Findcode,uLen))		
        {
            Addr_Hook = (ULONG)(uOriginAddr+i);
            break;
        }
    }
    return Addr_Hook;
}


BOOL ValidateCurrentProcessIsDNF(PCLIENT_ID ClientId)
{
	if ((UINT)ClientId->UniqueProcess==1628)
	{
		return TRUE;
	}
	else  
	{
		return FALSE;
	}
}

/************************************************************************/
/* 自定义的 NtOpenProcess，用来实现 InLine Hook Kernel API
/************************************************************************/
__declspec (naked)
NTSTATUS InLineHookNtOpenProcess(
    __out PHANDLE ProcessHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt PCLIENT_ID ClientId
    )
{
    __asm
    {
        push    dword ptr [ebp-38h]
        push    dword ptr [ebp-30h]
    }
   
    /* 开始过滤 */
    if(ValidateCurrentProcessIsDNF(ClientId) == TRUE)
    {
        __asm
        {
            /* 如果是 DNF 进程调用的话，则调用已经被 TP Hook 的 NtOpenProcess */
            jmp		uTPHookedNtOpenProcessJmpAddr
        }
    }

    __asm
    {
        /* 如果不是 DNF 进程调用的话，则调用 ntoskrnl.exe 中的 NtOpenProcess */
		
        call    uOriginObOpenObjectByPointerAddr

        jmp     uMyHookedNtOpenProcessJmpAddr
    }
}


/************************************************************************/
/* 安装钩子从而过掉 TP 保护所 Hook 的 NtOpenProcess - 让 TP 失效
/************************************************************************/
VOID InstallPassTPNtOpenProcess()
{
    CHAR szCode[7] = 
    {
        (char)0xff,
        (char)0x75,
        (char)0xc8,
        (char)0xff,
        (char)0x75,
        (char)0xd0,
        (char)0xe8
    };
   
    /* 获取原生的 NtOpenProcess 和 ObOpenObjectByPointer 的地址 */
    uOriginNtOpenProcessAddr = GetFunctionAddr(L"NtOpenProcess");
    uOriginObOpenObjectByPointerAddr = GetFunctionAddr(L"ObOpenObjectByPointer");
   
    /* 从 NtOpenProcess 这个地址开始搜索长度为 7 的特征码字符串，得到的地址将会被安装 InLine Hook */
    uMyHookedNtOpenProcessAddr = SearchFeature( (char *)uOriginNtOpenProcessAddr, szCode, 7, 640);
   
    /* 计算出自定义 InLine Hook 的跳转地址 */
    uMyHookedNtOpenProcessJmpAddr = uMyHookedNtOpenProcessAddr + 11;
   
    /* 计算出 TP InLine Hook 的跳转地址 */
    uTPHookedNtOpenProcessJmpAddr = uMyHookedNtOpenProcessAddr + 6;
   
    /* 安装一个 InLine Hook */
    InstallInLineHook(uMyHookedNtOpenProcessAddr, (ULONG)InLineHookNtOpenProcess, (ULONG)g_OrigNtOpenProcess, 6);
   
    KdPrint(("Pass TP - NtOpenProcess Installed."));
}
                                

/************************************************************************/
/*  自定义的 NtOpenThread，用来实现 InLine Hook Kernel API
/************************************************************************/
__declspec (naked)
NTSTATUS InLineHookNtOpenThread(
    __out PHANDLE ThreadHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt PCLIENT_ID ClientId
    )
{
	__asm
	{
		push    dword ptr [ebp-34h]
		push    dword ptr [ebp-28h]
	}

	/* 开始过滤 */
	if(ValidateCurrentProcessIsDNF(ClientId))
	{
		__asm
		{
			/* 如果是 DNF 进程调用的话，则调用已经被 TP Hook 的 NtOpenThread */
			jmp        uTPHookedNtOpenThreadJmpAddr
		}
	}
	__asm
	{
		/* 如果不是 DNF 进程调用的话，则调用 ntoskrnl.exe 中的 NtOpenThread */
		call    uOriginObOpenObjectByPointerAddr
		jmp     uMyHookedNtOpenThreadJmpAddr
	}
}

/************************************************************************/
/* 安装钩子从而过掉 TP 保护所 Hook 的 NtOpenThread - 让 TP 失效
/************************************************************************/
VOID InstallPassTPNtOpenThread()
{
    CHAR szCode[7] = 
    {
        (char)0xff,
        (char)0x75,
        (char)0xcc,
        (char)0xff,
        (char)0x75,
        (char)0xd8,
        (char)0xe8
    };
   
	/* 获取原生的 NtOpenThread 和 ObOpenObjectByPointer 的地址 */
	uOriginNtOpenThreadAddr = GetFunctionAddr(L"NtOpenThread");
	uOriginObOpenObjectByPointerAddr = GetFunctionAddr(L"ObOpenObjectByPointer");

	/* 从 NtOpenThread 这个地址开始搜索长度为 7 的特征码字符串，得到的地址将会被安装 InLine Hook */
	uMyHookedNtOpenThreadAddr = SearchFeature((char *)uOriginNtOpenThreadAddr, szCode, 7,620);
	uMyHookedNtOpenThreadJmpAddr = uMyHookedNtOpenThreadAddr + 11;
	uTPHookedNtOpenThreadJmpAddr = uMyHookedNtOpenThreadAddr + 6;

	InstallInLineHook(uMyHookedNtOpenThreadAddr, (ULONG)InLineHookNtOpenThread,(ULONG)g_OrigNtOpenThread, 6);

	KdPrint(("Pass TP - NtOpenThread Installed."));
}
							


/************************************************************************/
/* UnHook NtOpenThread
/************************************************************************/
VOID UnInstallPassTPNtOpenThread()
{
	UnInstallInLineHook(uMyHookedNtOpenThreadAddr, (ULONG)g_OrigNtOpenThread, 6);

	KdPrint(("Pass TP - NtOpenThread UnInstalled."));
}
	
/************************************************************************/
/* UnHook NtOpenProcess
/************************************************************************/
VOID UnInstallPassTPNtOpenProcess()
{
	UnInstallInLineHook(uMyHookedNtOpenProcessAddr, (ULONG)g_OrigNtOpenProcess, 6);

	KdPrint(("Pass TP - NtOpenProcess UnInstalled."));
}

VOID OnUnload( IN PDRIVER_OBJECT DriverObject )
{
    DbgPrint("My Driver Unloaded!");
	UnInstallPassTPNtOpenProcess();
	UnInstallPassTPNtOpenThread();
}

NTSTATUS DriverEntry( IN PDRIVER_OBJECT theDriverObject, IN PUNICODE_STRING theRegistryPath )
{
    DbgPrint("My Driver Loaded!");
    theDriverObject->DriverUnload = OnUnload;
	
	//_asm int 3

	InstallPassTPNtOpenProcess();
	InstallPassTPNtOpenThread();

    return STATUS_SUCCESS;
} 
