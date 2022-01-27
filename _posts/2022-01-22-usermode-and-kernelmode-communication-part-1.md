---
title: "User to Kernel Mode Communication:  Part 1"
date: 2022-01-22T11:49:59.552Z
classes: wide
---
### Kernel Crash Course

Kernel mode programming refers to kernel device drivers running in kernel mode/space. When developing for the kernel, one of the first things to grasp is when and how to write code here. When something fails (an unhandled exception occurs), the system will bugcheck (BSOD). This is a stark contrast from usermode, where when the same thing occurs, the application simply terminates. Which is why a fundamental rule is to only write code that runs in the kernel because it needs to perform a kernel level task. We will just refer to our kernel program as the *driver*, and our usermode program as a *client*. Drivers are classically written in *C*. Writing in *C* as opposed to *C++* means there is less abstraction involved. This generally means you'll write more code, but to the advantage that the program's behavior is more explicitly defined by you. Since I don't want this article to revolve around entry level topics about the differences, here's a quick rundown.

![](/assets/images/kernel_vs_user.png)

*Credit:  Pavel Yosifovich*

One of the key takeaways that can save headaches is that when `IRQL >= DISPATCH_LEVEL`, the memory accessed must be resident. Otherwise, an unhandled page-fault will occur. The scheduler which runs at `DISPATCH_LEVEL` will not be able to context-switch. This is because the faulting thread is running at the same IRQL and therefore can't be interrupted. By default, userspace applications and drivers run at `PASSIVE_LEVEL`. Another thing to note is the structured exception handling (SEH) usually provided in windows, will not work when `IRQL >= DISPATCH_LEVEL`.

There can be some uncertainty for choosing to implement certain functionality in the *driver* versus on the *client*.  I'll be laying out some core fundamentals here and these can be adjusted based on needs.  Also, we will review the types of communication possible and implement one of these ourselves today.  I **highly** recommend [this](https://voidsec.com/windows-drivers-reverse-engineering-methodology/) article supplement any further questions on the topic of drivers and getting started.

### How Communication Works

Some may wonder, "Why not write all my code in the driver and call it a day?". In the end, it depends on what functionality the developer needs to provide and what they're willing to sacrifice. It is entirely possible to have a kernel-mode driver without a client, but we will save that for another guide in the future. The normal interface for client and driver communication is handled by the Kernel-Mode I/O Manager. IRP packets are used to send commands and data between them. In order for this interface to work, there needs be a driver object created which is done automatically when the driver is loaded. Each driver object contains its' own `MajorFunction` table. These major functions are essentially callbacks that are defined by us for various windows api calls.

```c
  DriverObject->MajorFunction[IRP_MJ_CREATE] = Create;
  DriverObject->MajorFunction[IRP_MJ_CLOSE] = Close;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
  DriverObject->DriverUnload = Unload;
```

The important one here is `IRP_MJ_DEVICE_CONTROL` which gets triggered when `DeviceIoControl` is called with a handle to the corresponding device object created in this driver object.

### Our Scenario

A mapper simulates the process of the windows loader. At its core, it allocates memory for an image, copies it to that location, and handles relocations before executing the entrypoint.  In this case, a driver object isn't created. This is different from using the standard provided mechanism to load a driver, which must be signed.

In our situation, we will manually map our driver into the kernel.  Here's what this will look like..

![](/assets/images/userkernel-copy-of-communication.drawio.png)

As mentioned earlier, since our driver is manually mapped it has no driver object associated with it.  We still want to communicate with our driver though, so we need to find an alternate communication solution. Fortunately, there are many driver objects that already exist for us to use! Through Direct Kernel Object Manipulation (DKOM), we can swap out the pointers in the driver object's `MajorFunction` table to our own. 

### Implementation

Here's how to do this from project Diglett.

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

Now, when any usermode application makes a `DeviceIoControl` call using a handle to the `Null` driver's device object, it will invoke `Hk_DeviceControl`. Since any program could be executing our hook, we need to filter out the calls. We can use the data passed in through the `Irp` packet processed by the I/O manager from our client. The `IoControlCode` can be defined to something unique for our purposes.

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