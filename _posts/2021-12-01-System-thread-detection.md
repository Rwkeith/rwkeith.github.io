---
title: System Thread Detection
header:
  teaser: /assets/images/500x300.png
categories:
  - Jekyll
tags:
  - update
date: 2021-12-23T22:22:12.183Z
classes: wide
---
### Overview

Various anti-cheat vendors use several methods to detect cheats and prevent programs from modifying or tampering with the game process. This series will cover known heuristic methods being used today. Our topic will be in context with windows internals. Today this post is on detecting threads executing in Kernel memory.  Lets dive in!

### About Threads

First we will look at some undocumented structures used by `ntoskrnl.exe`.  A thread object is identified by a structure called `_ETHREAD`

```
struct _ETHREAD
{
    struct _KTHREAD Tcb;                                                    //0x0
    union _LARGE_INTEGER CreateTime;                                        //0x600
    union
    {
        union _LARGE_INTEGER ExitTime;                                      //0x608
        struct _LIST_ENTRY KeyedWaitChain;                                  //0x608
    };
    union
    {
        struct _LIST_ENTRY PostBlockList;                                   //0x618
        struct
        {
            VOID* ForwardLinkShadow;                                        //0x618
            VOID* StartAddress;                                             //0x620
        };
    ...   (etc.)
    VOID* Win32StartAddress;
}
```

Here we see `Tcb` and `Win32StartAddress` which both hold some useful information about the thread in our case.  Here's an except of `_KTHREAD`

```
struct _KTHREAD
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
    ...


    VOID* InitialStack;                                                     //0x28
    VOID* volatile StackLimit;                                              //0x30
    VOID* StackBase;                                                        //0x38
    ULONGLONG ThreadLock;                                                   //0x40
    ...
    VOID* KernelStack;
    ...

}
```

Due to the nature of these structures being undocumented, the offsets can vary between windows versions. Signatures can be created though to find the correct offset locations. Above, we have `KernelStack` which holds a pointer to the threads' stack. This will be used to determine if the thread is suspicious. Now we must enumerate through the threads. When using thread id's, note that they are a multiple of 4. We also check to ensure that the thread belongs to the system process by getting the process id of the thread and comparing it to our thread's process id.

```cpp
// current process is the system process
thisEPROC = pPsGetCurrentProcess();
for (size_t currentThreadId = 4; currentThreadId < 0x5000; currentThreadId += 4)
{
    status = pPsLookupThreadByThreadId((HANDLE)currentThreadId, &threadObject);

    processObject = pIoThreadToProcess(threadObject);
    processID = pPsGetProcessId(processObject);

    if (processID == systemProcId)
       // do checks...
}
```

We shouldn't try to copy a thread's stack while it's executing as the stack will constantly be changing. The thread needs to be in a `Waiting` state. To do this safely, we first acquire a lock to the thread. This means that as we enumerate the threads, we have to skip stack examination of threads that are not Waiting.

```cpp
BOOL Utility::LockThread(_In_ PKTHREAD Thread, _Out_ KIRQL * Irql)
{
    KIRQL currentIrql;
    UINT64 ThreadLockOffset;
    KSPIN_LOCK* threadLock;

    if (Thread && Irql)
    {
       ThreadLockOffset = GetThreadLockOffset();
       threadLock = (PKSPIN_LOCK)((BYTE*)Thread + ThreadLockOffset);
       if (threadLock && ThreadLockOffset)
       {
           currentIrql = KeGetCurrentIrql();
           // set cr8[3:0] (interrupt mask)
           __writecr8(0xC);
           *Irql = currentIrql;
           // raise our IRQL so our thread doesn't get interrupted
           KeAcquireSpinLockAtDpcLevel(threadLock);
           currentIrql = KeGetCurrentIrql();
           return SUCCESS;
       }
       else
       {
           return FAIL;
       }
    }
    else
    {
        return FAIL;
    }
}
```

If the thread is in a `Running` state, locking it won't halt the thread. This is why we need to check if the thread is in a waiting state after its been locked. You could use `NtSuspendThread` and `NtResumeThread` to change the thread's state. However, this is probably ill-advised for system stability concerns. The `State` member in `_KTHREAD` holds the thread's current state. To find the offset, we can scan for it in a function that references it. `KeAlertThread` seems like it would need to access that member. Knowing the correct offset already and then loading `ntoskrnl.exe` into Ghidra, we can quickly see where this function accesses this member

![](/assets/images/kealertthreadstateoffset.png "KeAlertThread")

![](/assets/images/threadstateaccessinstr.png "thread state member access")

The offset value here is `0x184`. Now it's trivial to write a function to pattern match the bytes at this instruction and pull the offset bytes. Here's a quick and dirty example

```cpp
BOOLEAN threadStatePatternMatch(_In_ BYTE* address, _Inout_ UINT32** outOffset, _In_ UINT32 range)
{
    for (BYTE* currByte = address; currByte < (address + range); currByte++)
    {
        if (currByte[0] == threadStatePattern[0]
            && currByte[1] == threadStatePattern[1]
            && currByte[6] == threadStatePattern[6]
            && currByte[7] == threadStatePattern[7])
        {
            *outOffset = (UINT32*)((BYTE*)currByte + 2);
            return SUCCESS;
        }
    }
    return FAIL;
}
```


Here's the checks the thread needs to pass in order to be examined

```cpp
if (isSystemThread             // is a system thread
        && threadStateOffset       // found all the offsets we needed for stack examination
        && kernelStackOffset
        && stackBase
        && threadStackLimit
        && (PKTHREAD)threadObject != KeGetCurrentThread())  // the thread being examined isn't ours
{
       StackWalkThread(threadObject, &stackBuffer);
}
```

Two key functions can be used for unwinding the stack to get the proper rip / rsp values from each frame: `RtlLookupFunctionEntry` and `RtlVirtualUnwind`. The first rip should be within the address range of ntoskrnl since that's where threads are created from.

```cpp
if (startRip >= ntosTextBase && startRip < ntosTextBase + sectionVa)
{
    context->Rip = startRip;
    context->Rsp = (DWORD64)(stackBuffer + 8);
    for (size_t i = 0; i < 0x20; i++)
    {
        rip = context->Rip;
        rsp = context->Rsp;
        stackwalkBuffer->Entry[stackwalkBuffer->EntryCount].RipValue = rip;
        stackwalkBuffer->Entry[stackwalkBuffer->EntryCount++].RspValue = rsp;
        if (rip < (UINT64)MmSystemRangeStart || rsp < (UINT64)MmSystemRangeStart)
            break;

        functionTableEntry = pRtlLookupFunctionEntry(rip, (PDWORD64)&moduleBase, 0);
                            
        if (!functionTableEntry)
            break;
        pRtlVirtualUnwind(0, moduleBase, context->Rip, functionTableEntry, context, (PVOID*)&handlerData, (PDWORD64)&establisherFrame, 0);
                            
        if (!context->Rip)
        {
            stackwalkBuffer->Succeeded = 1;
            break;
        }
    }
}
```

Now we should also unlock the thread so it can be free to get scheduled again.

```
threadLockOffset = GetThreadLockOffset();
threadLock = (KSPIN_LOCK*)((BYTE*)threadObject + threadLockOffset);

if (threadLockOffset)
{
    if (threadLock != 0)
    {
        KeReleaseSpinLockFromDpcLevel(threadLock);
        __writecr8(oldIrql);
    }
}
```

### Detecting Suspicious Threads

Taking the previous information, we can simply use `ZwQuerySystemInformation` with class `SystemModuleInformation` to enumerate all the system modules and compare the address ranges to the values in the stacks we are examining.  If any of thread's rip or rsp values lie outside of the legit module ranges, we can flag this as suspicious behavior.  Below is a simple way to check.

```cpp
BOOLEAN CheckModulesForAddress(UINT64 address, PRTL_PROCESS_MODULES systemMods)
{

    RTL_PROCESS_MODULE_INFORMATION sysMod;
    for (size_t i = 0; i < systemMods->NumberOfModules; i++)
    {
        sysMod = systemMods->Modules[i];

        if ((UINT64)sysMod.ImageBase < address && address < ((UINT64)sysMod.ImageBase + sysMod.ImageSize))
        {
            return SUCCESS;
        }
    }

    return FAIL;
}
```

Without relying on the stack, we can also get the thread's start address by simply getting the `Win32StartAddress` value in `_ETHREAD` using `NtQueryInformationTHread` like so

```cpp
NTSTATUS Utility::GetThreadStartAddr(_In_ PETHREAD threadObject, _Out_ uintptr_t* pStartAddr)
{
    *pStartAddr = NULL;
    HANDLE hThread;
    NTSTATUS status;

    if (!NT_SUCCESS(status = ObOpenObjectByPointer(threadObject, OBJ_KERNEL_HANDLE, nullptr, GENERIC_READ, *PsThreadType, KernelMode, &hThread))) {
        LogError("ObOpenObjectByPointer failed.\n");
        return status;
    }
    
    uintptr_t startAddr = NULL;
    ULONG returnedBytes;
    
    if (!NT_SUCCESS(status = pNtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &startAddr, sizeof(startAddr), &returnedBytes))) {
        LogError("NtQueryInformationThread failed.\n");
        NtClose(hThread);
        return status;
    }

    *pStartAddr = startAddr;
    NtClose(hThread);
    return STATUS_SUCCESS;
}
```

Now that we know how to examine a thread and deem it suspicious, we could do further analysis to decide our actions which will be covered in a later article.  Lets move on to how these methods could be mitigated.

### Mitigations