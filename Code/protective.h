//
//  protective.h
//  ShowStart
//
//  Created by sun on 2018/12/6.
//  Copyright © 2018年 taihe. All rights reserved.
//

#ifndef protective_h
#define protective_h

#import <Foundation/Foundation.h>

/*
 这些函数我们要保证其安全性，所以检测函数要是一个inline函数，确保攻击者不能简单地替换该函数来跳过检测。 使用 __attribute__((always_inline)) ,表示强制编译器进行inline编译，因为单纯的声明inline，可能编译器并不一定会内联，所以需要强制声明。
 */
/**
 禁止调试
 */
inline __attribute__((always_inline)) void antiDebug(void);

/**
 检查 Mach-O 文件 __RESTRICT 标识, 如果未找到, 则表示动态库注入被破解了
 在Xcode -> Target -> Build Settings -> Other Linker Flags -> 加入 -Wl,-sectcreate,__RESTRICT,__restrict,/dev/null
 */
inline __attribute__((always_inline)) BOOL checkRestrict(void);


/**
 检查二进制文件是否被解密
 提交到AppStore加密后的文件，会带上一个 LC_ENCRYPTION_INFO (LC_ENCRYPTION_INFO_64 64位)的 macho load command ,如下：
 Load command 12
     cmd LC_ENCRYPTION_INFO_64
     cmdsize 24
     cryptoff 16384
     cryptsize 2719744
     cryptid 1
     pad 0

 cryptid 值为1 则是加密状态
 通过如下命令查看
 otool -l mach-o file path | grep cryptid
 cryptid 1

 @return YES 加密 NO 解密
 */
inline __attribute__((always_inline)) BOOL isBinaryEncrypted(void);


/**
 检查是否有调试器

 @return YES 有调试器运行 NO 没有
 */
inline __attribute__((always_inline)) BOOL isDebuggerPresent(void);


/**
 汇编实现 exit 函数
 */
inline __attribute__((always_inline)) void sysexit(void);
#endif /* protective_h */
