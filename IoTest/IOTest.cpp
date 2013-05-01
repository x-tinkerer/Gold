// IOTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "windows.h"

#define IOCTL_BUFFERED_IO\
		CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define IOCTL_INDIRECT_IO\
		CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_IN_DIRECT,FILE_ANY_ACCESS)

#define IOCTL_NEITHER_IO\
		CTL_CODE(FILE_DEVICE_UNKNOWN,0x802,METHOD_NEITHER,FILE_ANY_ACCESS)

int _tmain(int argc, _TCHAR* argv[])
{
	HANDLE hFile;
	hFile= CreateFileA(
		"\\\\.\\Demo0",
		GENERIC_READ|GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
		);

	if (INVALID_HANDLE_VALUE == hFile)
	{
		printf("CreateFile Failure, err=%d \n",GetLastError());
		return 0;
	}

	DWORD bRet,dwRet;
	char Buffer[20];

#if 0
	bRet= WriteFile(hFile,"I Love U",8,&dwRet,NULL);
	if (!bRet)
	{
		printf("WriteFile Failure, err=%d \n",GetLastError());

		CloseHandle(hFile);

		return 0;
	}

	bRet= ReadFile(hFile,Buffer,20,&dwRet,NULL);
	if (!bRet)
	{
		printf("ReadFile Failure, err=%d \n",GetLastError());

		CloseHandle(hFile);

		return 0;
	}

	printf("ReadFile Buffer:%s Len:%d \n",Buffer,dwRet);
	return 0;

#endif

#if 1

	bRet = DeviceIoControl(hFile,IOCTL_BUFFERED_IO,"Testbuffer",10,Buffer,20,&dwRet,NULL);
	if (!bRet)
	{
		printf("DeviceIoControl Failure, err=%d \n",GetLastError());

		CloseHandle(hFile);

		return 0;
	}
	printf("DeviceIoControl IOCTL_BUFFERED_IO Buffer:%s   Len:%d \n",Buffer,dwRet);

	bRet = DeviceIoControl(hFile,IOCTL_INDIRECT_IO,NULL,0,Buffer,20,&dwRet,NULL);
	if (!bRet)
	{
		printf("DeviceIoControl Failure, err=%d \n",GetLastError());

		CloseHandle(hFile);

		return 0;
	}
	printf("DeviceIoControl IOCTL_INDIRECT_IO Buffer:%s Len:%d \n",Buffer,dwRet);

	bRet = DeviceIoControl(hFile,IOCTL_NEITHER_IO,"Hello World",11,Buffer,20,&dwRet,NULL);
	if (!bRet)
	{
		printf("DeviceIoControl Failure, err=%d \n",GetLastError());

		CloseHandle(hFile);

		return 0;
	}
	printf("DeviceIoControl IOCTL_NEITHER_IO Buffer:%s Len:%d \n",Buffer,dwRet);
#endif

}

