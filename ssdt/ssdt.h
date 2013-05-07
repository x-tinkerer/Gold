//IOCTL.h
#define	FILE_DRIVER_SSDT	0x0000420
#define	SystemModuleInfo	0x0B

#define	DRIVER_NAME		L"\\Device\\SSDT"
#define	DEVICE_NAME		L"\\DosDevices\\SSDT"

#ifndef CTL_CODE
#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)
#endif // CTL_CODE

#ifndef METHOD_NEITHER
#define METHOD_NEITHER 3
#endif // METHOD_NEITHER

#define IOCTL_TCP_QUERY_INFORMATION_EX 0x00120003
#define	HTONS(a)	(((0xff&a)<<8)+((0xff00&a)>>8))

#define TCPPORT	0
#define UDPPORT	1

typedef struct _CONNINFO102
{
	ULONG	status;
	ULONG	src_addr;
	USHORT	src_port;
	USHORT	unk1;
	ULONG	dst_addr;
	USHORT	dst_port;
	USHORT	unk2;
	ULONG	pid;
} CONNINFO102,*PCONNINFO102;

typedef	struct _UDPCONNINFO
{
	ULONG	src_addr;
	USHORT	src_port;
	ULONG	pid;
}	UDPCONNINFO,*PUDPCONNINFO;

NTSTATUS	
GetObjectByName(
				OUT HANDLE *FileHandle,
				OUT PFILE_OBJECT	*FileObject,
				IN WCHAR	*DeviceName
				);

PVOID		
EnumPortInformation(
					OUT PULONG	OutLength,
					IN	USHORT	PortType
	);


//////////////////////////////////////////////////////////////////////////
//SSDT 结构体
typedef struct _tagSSDT {
    PVOID pvSSDTBase;
    PVOID pvServiceCounterTable;
    ULONG ulNumberOfServices;
    PVOID pvParamTableBase;
} MYSSDT, *PMYSSDT;
/////////////////////////////////////////////////////////////////////////
// ModuleInfo 结构体
typedef struct ModuleInfo_t {
	ULONG Unused;
	ULONG Always0;
	ULONG ModuleBaseAddress;
	ULONG ModuleSize;
	ULONG Unknown;
	ULONG ModuleEntryIndex;
	/* Length of module name not including the path, this field contains valid value only for NTOSKRNL module*/
	USHORT ModuleNameLength; 
	USHORT ModulePathLength; /*Length of 'directory path' part of modulename*/
	char ModuleName[256];
} DRIVERMODULEINFO, *PDRIVERMODULEINFO;
////////////////////////////////////////////////////////////////////
//获取SSDT结构
#define IOCTL_GETSSDT  (ULONG)CTL_CODE( FILE_DRIVER_SSDT, 0x01, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA )

//设置SSDT结构
#define IOCTL_SETSSDT  (ULONG)CTL_CODE( FILE_DRIVER_SSDT, 0x02, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA )

//查询SSDT HOOK函数地址
#define IOCTL_GETHOOK  (ULONG)CTL_CODE( FILE_DRIVER_SSDT, 0x03, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA )

//设置SSDT HOOK函数地址
#define IOCTL_SETHOOK  (ULONG)CTL_CODE( FILE_DRIVER_SSDT, 0x04, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA )

//把NtQuerySystemInformation地址传到驱动
#define IOCTL_QSIADDR  (ULONG)CTL_CODE( FILE_DRIVER_SSDT, 0x05, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA )

//把NtDeviceIoControlFile地址传到驱动
#define IOCTL_DICFADDR  (ULONG)CTL_CODE( FILE_DRIVER_SSDT, 0x06, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA )

//强杀进程
#define IOCTL_KILL  (ULONG)CTL_CODE( FILE_DRIVER_SSDT, 0x07, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA )

//开启注册表保护
#define IOCTL_REG_PROTECTION  (ULONG)CTL_CODE( FILE_DRIVER_SSDT, 0x08, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA )

//停止注册表保护
#define IOCTL_STOP_PROTECTION  (ULONG)CTL_CODE( FILE_DRIVER_SSDT, 0x09, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA )

//把事件传到驱动
#define IOCTL_SAVE_EVENT  (ULONG)CTL_CODE( FILE_DRIVER_SSDT, 0x10, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA )

//获得注册表信息
#define IOCTL_REGISTRY_INFO  (ULONG)CTL_CODE( FILE_DRIVER_SSDT, 0x11, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA )

//允许修改
#define IOCTL_ALLOW_MODIFY  (ULONG)CTL_CODE( FILE_DRIVER_SSDT, 0x12, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA )

//枚举TCP
#define IOCTL_ENUMTCP (ULONG)CTL_CODE( FILE_DRIVER_SSDT, 0x13, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA )

//枚举UDP
#define IOCTL_ENUMUDP (ULONG)CTL_CODE( FILE_DRIVER_SSDT, 0x14, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA )
