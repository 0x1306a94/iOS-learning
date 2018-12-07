//
//  protective.m
//  ShowStart
//
//  Created by sun on 2018/12/6.
//  Copyright © 2018年 taihe. All rights reserved.
//

#import "protective.h"

#import <mach-o/getsect.h>
#import <mach-o/fat.h>
#import <mach-o/loader.h>
#import <dlfcn.h>
#import </usr/include/sys/ptrace.h>
#import <sys/sysctl.h>
#import <mach/task.h>
#import <mach/mach_init.h>
#include <termios.h>
#include <sys/ioctl.h>

/*
 这些函数我们要保证其安全性，所以检测函数要是一个inline函数，确保攻击者不能简单地替换该函数来跳过检测。 使用 __attribute__((always_inline)) ,表示强制编译器进行inline编译，因为单纯的声明inline，可能编译器并不一定会内联，所以需要强制声明。
 */
/**
 禁止调试
 */
inline __attribute__((always_inline)) void antiDebug(void) {
#ifdef __arm64__
    asm volatile(
                 "mov x0, #26 \n"
                 "mov x1, #31 \n"
                 "mov x2, #0 \n"
                 "mov x3, #0 \n"
                 "mov x16, #0 \n"
                 "svc #128 \n"
                 );
#elif __arm__
    asm volatile(
                 "mov r0, #31 \n"
                 "mov r1, #0 \n"
                 "mov r2, #0 \n"
                 "mov r12, #26 \n"
                 "svc #80 \n"
                 );
#endif
    return;
}

/**
 检查 Mach-O 文件 __RESTRICT 标识, 如果未找到, 则表示动态库注入被破解了
 在Xcode -> Target -> Build Settings -> Other Linker Flags -> 加入 -Wl,-sectcreate,__RESTRICT,__restrict,/dev/null
 */
inline __attribute__((always_inline)) BOOL checkRestrict(void) {
    const struct section_64 *secstate = getsectbyname("__RESTRICT", "__restrict");
    return secstate != NULL;
}

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
inline __attribute__((always_inline)) BOOL isBinaryEncrypted(void) {
    // checking current binary's LC_ENCRYPTION_INFO
    const void *binaryBase = NULL;
    struct load_command *machoCmd = NULL;
    const struct mach_header *machoHeader = NULL;

    NSString *path = [[NSBundle mainBundle] executablePath];
    NSData *filedata = [NSData dataWithContentsOfFile:path];
    binaryBase = (char *)[filedata bytes];

    machoHeader = (const struct mach_header *) binaryBase;

    if(machoHeader->magic == FAT_CIGAM)
    {
        unsigned int offset = 0;
        struct fat_arch *fatArch = (struct fat_arch *)((struct fat_header *)machoHeader + 1);
        struct fat_header *fatHeader = (struct fat_header *)machoHeader;
        for(uint32_t i = 0; i < ntohl(fatHeader->nfat_arch); i++)
        {
            if(sizeof(int *) == 4 && !(ntohl(fatArch->cputype) & CPU_ARCH_ABI64)) // check 32bit section for 32bit architecture
            {
                offset = ntohl(fatArch->offset);
                break;
            }
            else if(sizeof(int *) == 8 && (ntohl(fatArch->cputype) & CPU_ARCH_ABI64)) // and 64bit section for 64bit architecture
            {
                offset = ntohl(fatArch->offset);
                break;
            }
            fatArch = (struct fat_arch *)((uint8_t *)fatArch + sizeof(struct fat_arch));
        }
        machoHeader = (const struct mach_header *)((uint8_t *)machoHeader + offset);
    }
    if(machoHeader->magic == MH_MAGIC)    // 32bit
    {
        machoCmd = (struct load_command *)((struct mach_header *)machoHeader + 1);
    }
    else if(machoHeader->magic == MH_MAGIC_64)   // 64bit
    {
        machoCmd = (struct load_command *)((struct mach_header_64 *)machoHeader + 1);
    }
    for(uint32_t i=0; i < machoHeader->ncmds && machoCmd != NULL; i++){
        if(machoCmd->cmd == LC_ENCRYPTION_INFO)
        {
            struct encryption_info_command *cryptCmd = (struct encryption_info_command *) machoCmd;
            return cryptCmd->cryptid;
        }
        if(machoCmd->cmd == LC_ENCRYPTION_INFO_64)
        {
            struct encryption_info_command_64 *cryptCmd = (struct encryption_info_command_64 *) machoCmd;
            return cryptCmd->cryptid;
        }
        machoCmd = (struct load_command *)((uint8_t *)machoCmd + machoCmd->cmdsize);
    }
    return NO; // couldn't find cryptcmd
}

/**
 检查是否有调试器

 @return YES 有调试器运行 NO 没有
 */
inline __attribute__((always_inline)) BOOL isDebuggerPresent(void) {
    int name[4];                //指定查询信息的数组

    struct kinfo_proc info;     //查询的返回结果
    size_t info_size = sizeof(info);

    info.kp_proc.p_flag = 0;

    name[0] = CTL_KERN;
    name[1] = KERN_PROC;
    name[2] = KERN_PROC_PID;
    name[3] = getpid();

    if(sysctl(name, 4, &info, &info_size, NULL, 0) == -1){
        NSLog(@"sysctl error : %s", strerror(errno));
        return NO;
    }

    return ((info.kp_proc.p_flag & P_TRACED) != 0);
}

/**
 汇编实现 exit 函数 防止 exit 函数 被 hook
 */
inline __attribute__((always_inline)) void sysexit(void) {
#ifdef __arm64__
    asm volatile(
                 "mov X0, #1 \n"
                 "mov w16, #1 \n"
                 "svc #0x80 \n"
                );
#elif __arm__
    asm volatile(
                 "mov r0, #1 \n"
                 "mov ip, #1 \n"
                 "svc #0x80 \n"
                );
#endif
    return;
}
