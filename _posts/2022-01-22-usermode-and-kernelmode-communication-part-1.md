---
title: "User to Kernel Mode Communication:  Part 1"
date: 2022-01-27T10:52:09.536Z
classes: wide
---
### I﻿ntroduction

This article aims to provide an understanding of user-to-kernel communication on the x86 platform in Windows. If you already have some general knowledge, feel free to skip ahead.

### Kernel Crash Course

Kernel mode programming involves writing kernel device drivers that run in kernel mode. It's crucial to understand when and how to write code for the kernel. Unlike user mode, where an unhandled exception causes the application to terminate, a kernel mode failure leads to a system bugcheck (BSOD). Therefore, only write kernel code when it’s necessary for kernel-level tasks. We'll refer to our kernel program as the driver and our user mode program as the client. Drivers are typically written in C, but there are also some interesting workarounds to build using C++.

![](/assets/images/kernel_vs_user.png)



One key point to remember is that when `IRQL >= DISPATCH_LEVEL`, the accessed memory must be resident to avoid unhandled page-faults. The scheduler, running at `DISPATCH_LEVEL`, cannot context-switch because the faulting thread runs at the same IRQL and can't be interrupted. By default, both userspace applications and drivers run at `PASSIVE_LEVEL`. Note that structured exception handling (SEH) in Windows does not work at `IRQL >= DISPATCH_LEVEL`.



Choosing whether to implement certain functionality in the driver or client can be uncertain. Here, we’ll outline some core fundamentals which can be adjusted based on specific needs. We'll also review possible communication types and implement one of them. I **highly** recommend [this](https://voidsec.com/windows-drivers-reverse-engineering-methodology/) article supplement any further questions on the topic of drivers and getting started.

### How Communication Works

A common question is why not write all code in the driver. The answer depends on the functionality required and the trade-offs you're willing to make. While it's possible to have a kernel-mode driver without a client, we'll focus on the typical client-driver communication, which the Kernel-Mode I/O Manager handles using IRP packets.

To enable this interface, a driver object must be created when the driver loads, containing its own `MajorFunction` table. These major functions are callbacks we define for various Windows API calls:

```c
  DriverObject->MajorFunction[IRP_MJ_CREATE] = Create;
  DriverObject->MajorFunction[IRP_MJ_CLOSE] = Close;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
  DriverObject->DriverUnload = Unload;
```

The critical one here is `IRP_MJ_DEVICE_CONTROL`, which triggers when `DeviceIoControl` is called with a handle to the corresponding device object.

### Our Scenario

A mapper simulates the Windows loader by allocating memory for an image, copying it, handling relocations, and executing the entry point. Unlike standard driver loading, this method doesn’t create a driver object. We will manually map our driver into the kernel and communicate with it using existing driver objects via Direct Kernel Object Manipulation (DKOM).

In our situation, we will manually map our driver into the kernel.  Here's what this will look like..

![](/assets/images/userkernel-copy-of-communication.drawio.png)

As mentioned earlier, since our driver is manually mapped it has no driver object associated with it.  We still want to communicate with our driver though, so we need to find an alternate communication solution. Fortunately, there are many driver objects that already exist for us to use! Through Direct Kernel Object Manipulation (DKOM), we can swap out the pointers in the driver object's `MajorFunction` table to our own. 

### Implementation

Here's an example from project [Diglett](https://github.com/Rwkeith/Diglett):

```c
// Driver we want to communicate through
RtlInitUnicodeString(&driverName, L"\\Driver\\Null");

// Obtain a reference to the DriverObject
status = ObReferenceObjectByName(&driverName, OBJ_CASE_INSENSITIVE, NULL, 0,
    *IoDriverObjectType, KernelMode, NULL, (PVOID*)&DriverObject);

// Hook Null driver's MajorFunctions
for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
    //save the original pointer in case we want to restore it later
    gOriginalDispatchFunctionArray[i] = DriverObject->MajorFunction[i];
    //replace the pointer with our own pointer
    if (i == IRP_MJ_DEVICE_CONTROL)
    {
        DriverObject->MajorFunction[i] = Hk_DeviceControl;
        LogInfo("\tHooked IRP_MJ_DEVICE_CONTROL");
        LogInfo("\t\tOld: %p", gOriginalDispatchFunctionArray[i]);
        LogInfo("\t\tNew: %p", DriverObject->MajorFunction[i]);
    }
}
```



Now, any user mode application making a `DeviceIoControl` call using a handle to the `Null` driver's device object will invoke `Hk_DeviceControl`. Filter calls using the data passed through the IRP packet processed by the I/O manager from our client.  A custom `IoControlCode` can be defined as a magic/cookie value to filter against.

```c
NTSTATUS Hk_DeviceControl(PDEVICE_OBJECT tcpipDevObj, PIRP Irp)
{
    // Get Irp
    auto stack = IoGetCurrentIrpStackLocation(Irp);
    auto status = STATUS_SUCCESS;

    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
      // our unique code
      case IOCTL_ECHO_REQUEST: {
        LogInfo("IOCTL_ECHO_REQUEST received from our Client!\n");
        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ECHO_DATA))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        auto data = (PECHO_DATA)stack->Parameters.DeviceIoControl.Type3InputBuffer;

        if (data == nullptr)
        {
            status = STATUS_SUCCESS; // <- TEST
            //status = STATUS_INVALID_PARAMETER;
            break;
        }

        LogInfo("Echo request output: %s\n", data->strEcho);
        Irp->IoStatus.Status = CUSTOM_STATUS;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return CUSTOM_STATUS;
    }
      // all other codes
      default:
        LogInfo("Unrecognized IoControlCode, forwarding to original DeviceControl.\n");
        return origDeviceControl(tcpipDevObj, Irp);
    }
}
```

After all this is complete, we now have client to kernel communication without creating a driver object. Here's the end result with Diglett making 3 hooks in the driver object.

![](/assets/images/diglettdrvobjhooks.png)

### Counter-measures

It wouldn't feel like this article would be complete if I didn't show how this method of communication could be detected. Anti-cheat software is aware and indeed checks for these driver object hooks. Similarly to the previous detection method used in the article on thread stack-walking, the addresses can once again be used for heuristics.  If any of the addresses point to memory not occupied by any legitimately loaded module, it's suspicious behavior.  Project Nomad handles this effectively by enumerating through all of the driver objects and checking the `IRP_MJ_DEVICE_CONTROL` function table pointer.  It also does a couple more unique checks that are known methods.

```c
while (NT_SUCCESS(ZwQueryDirectoryObject(h, dirInfo, PAGE_SIZE, TRUE, FALSE, &ulContext, &returnedBytes)))
{
    isClean = true;
    PDRIVER_OBJECT pObj;
    wchar_t wsDriverName[100] = L"\\Driver\\";
    wcscat(wsDriverName, dirInfo->ObjectName.Buffer);
    UNICODE_STRING objName;
    objName.Length = objName.MaximumLength = wcslen(wsDriverName) * 2;
    objName.Buffer = wsDriverName;
    if (NT_SUCCESS(ObReferenceObjectByName(&objName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL, *IoDriverObjectType, KernelMode, nullptr, (PVOID*)&pObj)))
    {
        LogInfo("Checking driver object: %ls", wsDriverName);
        LogInfo("\t\tChecking ->MajorFunction[IRP_MJ_DEVICE_CONTROL]");
        if (!CheckModulesForAddress(reinterpret_cast<uintptr_t>(pObj->MajorFunction[IRP_MJ_DEVICE_CONTROL]), outProcMods)) {
            LogInfo("\t\t\t[SUSPICIOUS] %wZ driver has suspicious driver dispatch", pObj->DriverName);
            isClean = false;
        }

        LogInfo("\t\tChecking ->DriverStart");
        if (!CheckModulesForAddress((uintptr_t)pObj->DriverStart, outProcMods)) {
            LogInfo("\t\t\t[SUSPICIOUS] %wZ driver has suspicious DriverStart", pObj->DriverName);
            isClean = false;
        }

        LogInfo("\t\tChecking ->FastIoDispatch");
        if (reinterpret_cast<uintptr_t>(pObj->FastIoDispatch))
        {
            if (!CheckModulesForAddress(reinterpret_cast<uintptr_t>(pObj->FastIoDispatch->FastIoDeviceControl), outProcMods)) {
                LogInfo("\t\t\t[SUSPICIOUS] %wZ driver has suspicious FastIoDispatch->FastIoDeviceControl", pObj->DriverName);
                isClean = false;
            }
        }
        else
        {
            LogInfo("\t\t\tFastIoDispatch == NULL");
        }

        if (isClean)
        {
            LogInfo("Driver object clean.");
        }
        else
        {
            suspiciousDrivers++;
        }

        ObDereferenceObject(pObj);
    }
}
```

And finally the resulting output from above

![](/assets/images/nomaddrvobjscan.png)

### Hook Types and Conclusion

Various communication methods exist, some easier to detect than others. `Pointer hooks` in read/write protected regions are harder to detect compared to `in-line hooks` in the `.text` section. This article provides a primer on setting up communication between a manually mapped driver and client. Next, we’ll discuss memory-related topics. Thank you for reading!