---
title: "Usermode and Kernelmode Communication:  Part 1"
date: 2022-01-22T11:49:59.552Z
classes: wide
---
### Kernel Crash Course

When developing a tool or cheat one of the first things to grasp is the concepts and fundamental reasons of why or how to develop it. Kernel mode programming refers to kernel device drivers running in kernel mode/space. The kernel is a dangerous place to be. When something fails (an unhandled exception occurs), the system will bugcheck (BSOD). This is a stark contrast from usermode, where when the same thing occurs, the application simply terminates. Which is why a fundamental rule is to only write code that runs in the kernel because it needs to perform a kernel level task. We will just refer to our kernel program as the *driver*, and our usermode program as a *client*. Drivers are classically written in *C*. Writing in *C* as opposed to *C++* means there is less abstraction involved. This generally means you'll write more code, but to the advantage that the program's behavior is more explicitly defined by you.

People can have confusion on when it's necessary to write code for your *driver* versus code that runs on the *client*.  I'll be laying out the core fundamentals here and these can be adjusted based on your needs.  Also, we will review the types of communication possible and implement one of these ourselves today :)



###  When to Communicate?





### Types of Communication