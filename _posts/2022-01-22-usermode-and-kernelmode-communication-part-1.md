---
title: "Usermode and Kernelmode Communication:  Part 1"
date: 2022-01-22T11:49:59.552Z
classes: wide
---
### Kernel Crash Course

Kernel mode programming refers to kernel device drivers running in kernel mode/space. When developing for the kernel, one of the first things to grasp is when and how to write code here. When something fails (an unhandled exception occurs), the system will bugcheck (BSOD). This is a stark contrast from usermode, where when the same thing occurs, the application simply terminates. Which is why a fundamental rule is to only write code that runs in the kernel because it needs to perform a kernel level task. We will just refer to our kernel program as the *driver*, and our usermode program as a *client*. Drivers are classically written in *C*. Writing in *C* as opposed to *C++* means there is less abstraction involved. This generally means you'll write more code, but to the advantage that the program's behavior is more explicitly defined by you. Since I don't want this article to revolve around entry level topics about the differences, here's a quick rundown.

![](/assets/images/kernel_vs_user.png)

*Credit:  Pavel Yosifovich*



One of the biggest takeaways that will save you headaches is that when IRQL is >= dispatch-level, the memory you access must be in RAM.  Otherwise, you will encounter an unhandled page-fault. The scheduler which runs at dispatch-level (2), will not be able to wake since the faulting thread is running at the same IRQL and can't be interrupted. By default, you can assume you are at passive-level (0). Also note, that Structured Exception Handled (provided by default to handle exceptions), will not work when IRQL >= dispatch-level or when your driver is not mapped and loaded properly by the windows loader :)

People can have confusion on when it's necessary to write code for your *driver* versus code that runs on the *client*.  I'll be laying out the core fundamentals here and these can be adjusted based on your needs.  Also, we will review the types of communication possible and implement one of these ourselves today :)

### When to Communicate?

### Types of Communication