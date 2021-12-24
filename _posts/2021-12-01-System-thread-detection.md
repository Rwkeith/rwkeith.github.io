---
title: System Thread Detection
header:
  teaser: /assets/images/500x300.png
categories:
  - Jekyll
tags:
  - update
date: 2021-12-23T22:22:12.183Z
---
### Overview

Various anti-cheat vendors use several methods to detect cheats and prevent programs from modifying or tampering with the game process. This series will cover known heuristic methods being used today. Keep in mind  our topic is in context with windows internals. Today this post is on thread detection executing in Kernel.  Lets dive in!

### About Threads
First we will look at some undocumented structures used by ntoskrnl.  A thread object is identified by a structure called `_ETHREAD`

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
}
```

Here we see `Tcb` and `StartAddress` which hold some useful information about the thread in our case.  Here's an except of `_KTHREAD`

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

Due to the nature of being undocumented, these offsets can vary between versions. Signatures can be created though to find the correct offsets which we will see later. Above we have `KernelStack` which holds a pointer to the threads' stack.  

### Detecting Suspicious Threads
Taking the previous information, we can simply use `ZwQuerySystemInformation` with class `SystemModuleInformation` to enumerate all the system modules and compare the address ranges to the values in the stacks we are examining.  If any of thread's rip or rsp values lie outside of the legit module ranges, we can flag this as suspicious behavior.  Below is a simple way to check for this.

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

Jekyll also offers powerful support for code snippets:

```cpp
def print_hi(name)
  puts "Hi, #{name}"
end
print_hi('Tom')
#=> prints 'Hi, Tom' to STDOUT.
```

Check out the [Jekyll docs](http://jekyllrb.com/docs/home) for more info on how to get the most out of Jekyll. File all bugs/feature requests at [Jekyll's GitHub repo](https://github.com/jekyll/jekyll). If you have questions, you can ask them on [Jekyll Talk](https://talk.jekyllrb.com/).
