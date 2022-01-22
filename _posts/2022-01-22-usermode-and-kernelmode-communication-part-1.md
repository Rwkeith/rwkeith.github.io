---
title: "Usermode and Kernelmode Communication:  Part 1"
date: 2022-01-22T11:49:59.552Z
classes: wide
---
### Overview

When developing a tool or cheat one of the first things to grasp is the concepts and fundamental reasons of why or how to develop it. There is a lot of confusion on when it's necessary to write code for your driver versus code that runs in a client.  The answer is not so simple when several factors and motivations are involved. However, I'll be laying out the core fundamentals, and these can be adjusted based on your needs.  Also, we will review the types of communication possible and implement one of these ourselves today :)