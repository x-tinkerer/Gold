#include <ntddk.h>


#define IOCTL_BUFFERED_IO\
		CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define IOCTL_INDIRECT_IO\
		CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_IN_DIRECT,FILE_ANY_ACCESS)

#define IOCTL_NEITHER_IO\
		CTL_CODE(FILE_DEVICE_UNKNOWN,0x802,METHOD_NEITHER,FILE_ANY_ACCESS)

VOID UnloadDriver(IN PDRIVER_OBJECT DriverObject);

////////////////////定义所用到的全局变量///////////////


NTSTATUS DemoCreateClose(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp)
{
	Irp->IoStatus.Status=STATUS_SUCCESS;
	Irp->IoStatus.Information=0;

	IoCompleteRequest(Irp,IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DemoDefaultHandler(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp)
{
	Irp->IoStatus.Status=STATUS_NOT_SUPPORTED;
	Irp->IoStatus.Information=0;

	IoCompleteRequest(Irp,IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DemoReadWrite(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION pSP = IoGetCurrentIrpStackLocation(Irp);
	PVOID pBuffer = NULL;
	BOOLEAN bNeither = FALSE;
	ULONG uLen = 0;

	DbgPrint("DemoReadWrite \n");

	if(DeviceObject->Flags & DO_BUFFERED_IO)
	{
		DbgPrint("Flags :DO_BUFFERED_IO \n");
		pBuffer=Irp->AssociatedIrp.SystemBuffer;
	}
	else if (DeviceObject->Flags & DO_DIRECT_IO)
	{
		DbgPrint("Flags :DO_DIRECT_IO \n");
		pBuffer=MmGetSystemAddressForMdl(Irp->MdlAddress);
	}
	else
	{
		DbgPrint("Flags :Neither \n");
		bNeither=TRUE;

		pBuffer=Irp->UserBuffer;
	}

	switch (pSP->MajorFunction)
	{

	case IRP_MJ_READ:
		uLen=pSP->Parameters.Read.Length;
		uLen = uLen>10 ? 10 : uLen;
		DbgPrint("IRP_MJ_READ Read Len : %d \n",uLen=pSP->Parameters.Read.Length);

		if (FALSE==bNeither)
		{
			RtlCopyMemory(pBuffer,DeviceObject->DeviceExtension,uLen);
		}
		else
		{
			__try
			{
				ProbeForWrite(pBuffer,uLen,4);
				RtlCopyMemory(pBuffer,DeviceObject->DeviceExtension,uLen);
			}
			_except(EXCEPTION_EXECUTE_HANDLER)
			{
				DbgPrint("IRP_MJ_READ Exception!\n");
				status=STATUS_UNSUCCESSFUL;
			}

		}
		break;
	case IRP_MJ_WRITE:
		uLen=pSP->Parameters.Write.Length;
		uLen = uLen>10 ? 10 : uLen;
		DbgPrint("IRP_MJ_WRITE Write Len : %d \n",uLen=pSP->Parameters.Write.Length);

		if (FALSE==bNeither)
		{
			RtlCopyMemory(DeviceObject->DeviceExtension,pBuffer,uLen);
		}
		else
		{
			__try
			{
				ProbeForRead(pBuffer,uLen,4);
				RtlCopyMemory(DeviceObject->DeviceExtension,pBuffer,uLen);
			}
			_except(EXCEPTION_EXECUTE_HANDLER)
			{
				DbgPrint("IRP_MJ_WRITE Exception!\n");
				status=STATUS_UNSUCCESSFUL;
			}

		}
		break;
	}

	Irp->IoStatus.Status =status;
	Irp->IoStatus.Information = uLen;

	IoCompleteRequest(Irp,IO_NO_INCREMENT);
	
	return status;
}


NTSTATUS DemoDevControl(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION pSP = IoGetCurrentIrpStackLocation(Irp);

	ULONG uControlCode=pSP->Parameters.DeviceIoControl.IoControlCode;

	PVOID pInBuf = NULL,pOutBuf = NULL;
	ULONG uInLen = 0,uOutLen = 0;

	DbgPrint("DemoDevControl \n");

	uInLen=pSP->Parameters.DeviceIoControl.InputBufferLength;
	uInLen= uInLen>10 ? 10 :uInLen;

	uOutLen=pSP->Parameters.DeviceIoControl.OutputBufferLength;
	uOutLen= uOutLen>10 ? 10 :uOutLen;

	DbgPrint("uInLen : %d  uOutLen : %d\n",pSP->Parameters.DeviceIoControl.InputBufferLength,
		pSP->Parameters.DeviceIoControl.OutputBufferLength);


	switch (uControlCode)
	{

	case IOCTL_BUFFERED_IO:
		DbgPrint("IOCTL_BUFFERED_IO\n");
		pInBuf = pOutBuf =Irp->AssociatedIrp.SystemBuffer;

		if(uInLen)
		{
			RtlCopyMemory(DeviceObject->DeviceExtension,pInBuf,uInLen);
		}
		if(uOutLen)
		{
			RtlCopyMemory(pOutBuf,DeviceObject->DeviceExtension,uOutLen);
		}
		
		break;
	case IOCTL_INDIRECT_IO:

		DbgPrint("IOCTL_INDIRECT_IO\n");

		pInBuf = Irp->AssociatedIrp.SystemBuffer;
		pOutBuf= MmGetSystemAddressForMdl(Irp->MdlAddress);

		if(uInLen)
		{
			RtlCopyMemory(DeviceObject->DeviceExtension,pInBuf,uInLen);
		}
		if(uOutLen)
		{
			RtlCopyMemory(pOutBuf,DeviceObject->DeviceExtension,uOutLen);
		}
		
		break;
	case IOCTL_NEITHER_IO:
		DbgPrint("IOCTL_NEITHER_IO \n");

		pInBuf = pSP->Parameters.DeviceIoControl.Type3InputBuffer;
		pOutBuf= Irp->UserBuffer;

		__try
		{
			if(uInLen)
			{
				ProbeForRead(pInBuf,uInLen,4);
				RtlCopyMemory(DeviceObject->DeviceExtension,pInBuf,uInLen);
			}
			if(uOutLen)
			{
				ProbeForWrite(pOutBuf,uOutLen,4);
				RtlCopyMemory(pOutBuf,DeviceObject->DeviceExtension,uOutLen);
			}
		}
		_except(EXCEPTION_EXECUTE_HANDLER)
		{
			DbgPrint("IOCTL Exception!\n");
			status=STATUS_UNSUCCESSFUL;
		}
		break;
	}

	Irp->IoStatus.Status =status;
	Irp->IoStatus.Information = uOutLen;

	IoCompleteRequest(Irp,IO_NO_INCREMENT);
	
	return status;
}



NTSTATUS DriverEntry (IN PDRIVER_OBJECT DriverObject,IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	UNICODE_STRING  DeviceName,Win32Device;
	PDEVICE_OBJECT   DeviceObject=NULL;

	unsigned i;


	RtlInitUnicodeString(&DeviceName,L"\\Device\\Demo0");
	RtlInitUnicodeString(&Win32Device,L"\\DosDevices\\Demo0");

	for(i=0; i<=IRP_MJ_MAXIMUM_FUNCTION;i++)
	{
		DriverObject->MajorFunction[i]=DemoDefaultHandler;
	}

	//IRP 
	DriverObject->MajorFunction[IRP_MJ_CREATE]=DemoCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE]=DemoCreateClose;
	DriverObject->MajorFunction[IRP_MJ_READ]=DemoReadWrite;
	DriverObject->MajorFunction[IRP_MJ_WRITE]=DemoReadWrite;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]=DemoDevControl;

	DriverObject->DriverUnload=UnloadDriver;

   status = IoCreateDevice(
                DriverObject,
                10,                      
                &DeviceName,
                FILE_DEVICE_UNKNOWN,
                0,
                FALSE,
                & DeviceObject );

    if (!NT_SUCCESS( status )) 
    {

        DbgPrint(( "DriverEntry: Error creating control device object, status=%08x\n", status ));
        return status;
    }

   status = IoCreateSymbolicLink(
                (PUNICODE_STRING) &Win32Device,
                (PUNICODE_STRING) &DeviceName
                );

   if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(DeviceObject);
        return status;
    }
 

   DeviceObject->Flags &=DO_DEVICE_INITIALIZING;

  return status ;
}


VOID UnloadDriver(IN PDRIVER_OBJECT DriverObject)
{
 
	UNICODE_STRING  Win32Device;

	DbgPrint("UnloadDriver \n");

	RtlInitUnicodeString(&Win32Device,L"\\DosDevices\\Demo0");

	IoDeleteSymbolicLink(&Win32Device);

	IoDeleteDevice(DriverObject->DeviceObject);

	return STATUS_SUCCESS;
}

