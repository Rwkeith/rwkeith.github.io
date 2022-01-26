---
title: "Usermode and Kernelmode Communication:  Part 1"
date: 2022-01-22T11:49:59.552Z
classes: wide
---
### Kernel Crash Course

Kernel mode programming refers to kernel device drivers running in kernel mode/space. When developing for the kernel, one of the first things to grasp is when and how to write code here. When something fails (an unhandled exception occurs), the system will bugcheck (BSOD). This is a stark contrast from usermode, where when the same thing occurs, the application simply terminates. Which is why a fundamental rule is to only write code that runs in the kernel because it needs to perform a kernel level task. We will just refer to our kernel program as the *driver*, and our usermode program as a *client*. Drivers are classically written in *C*. Writing in *C* as opposed to *C++* means there is less abstraction involved. This generally means you'll write more code, but to the advantage that the program's behavior is more explicitly defined by you. Since I don't want this article to revolve around entry level topics about the differences, here's a quick rundown.

![](/assets/images/kernel_vs_user.png)

*Credit:  Pavel Yosifovich*

One of the biggest takeaways that can save headaches is that when `IRQL >= DISPATCH_LEVEL`, the memory accessed must be resident  Otherwise, an unhandled page-fault will occur. The scheduler which runs at `DISPATCH_LEVEL`, will not be able to context-switch since the faulting thread is running at the same IRQL and therefore can't be interrupted. By default, userspace applications and drivers run at `PASSIVE_LEVEL`. Another note is that structured exception handling (SEH), will not work when `IRQL >= DISPATCH_LEVEL`.

People can have confusion on when it's necessary to write code for the *driver* versus code that runs on the *client*.  I'll be laying out the core fundamentals here and these can be adjusted based on needs.  Also, we will review the types of communication possible and implement one of these ourselves today.  I **highly** recommend [this](https://voidsec.com/windows-drivers-reverse-engineering-methodology/) article supplement any further questions on the topic of drivers and getting started.

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

Things like, manual mapping, don't create driver objects. This is because that instead of using the standard provided mechanism to load a driver, which must be signed, a kernel mapper will: allocate memory in the kernel, copy the image to this memory, and then create a new thread that will then run the entry point of the image. 

In our situation, we're going to have a manually mapped driver in the kernel.  Here's what this will look like..

![](/assets/images/userkernel-copy-of-communication.drawio.png)

As mentioned earlier, since our driver was manually mapped it has no driver object associated with it.  We still want to communicate with our driver though, so we need to find an alternate communication solution. Fortunately,