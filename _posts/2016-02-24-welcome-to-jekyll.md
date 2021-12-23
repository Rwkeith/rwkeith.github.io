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

The threads object is identified by a structure called `_ETHREAD`

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

Here we see `Tcb` and `StartAddress` which hold some useful information about the thread in our case.  Examining `_KTHREAD`

```

```

You'll find this post in your `_posts` directory. Go ahead and edit it and re-build the site to see your changes. You can rebuild the site in many different ways, but the most common way is to run `jekyll serve`, which launches a web server and auto-regenerates your site when a file is updated.

To add new posts, simply add a file in the `_posts` directory that follows the convention `YYYY-MM-DD-name-of-post.ext` and includes the necessary front matter. Take a look at the source for this post to get an idea about how it works.

Jekyll also offers powerful support for code snippets:

```cpp
def print_hi(name)
  puts "Hi, #{name}"
end
print_hi('Tom')
#=> prints 'Hi, Tom' to STDOUT.
```

Check out the [Jekyll docs](http://jekyllrb.com/docs/home) for more info on how to get the most out of Jekyll. File all bugs/feature requests at [Jekyll's GitHub repo](https://github.com/jekyll/jekyll). If you have questions, you can ask them on [Jekyll Talk](https://talk.jekyllrb.com/).