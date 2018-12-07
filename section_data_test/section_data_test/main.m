//
//  main.m
//  test
//
//  Created by sun on 2018/12/7.
//  Copyright © 2018年 taihe. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach-o/getsect.h>
#import <mach-o/dyld.h>

#ifndef __LP64__
#define MACH_HEADER struct mach_header *
#else
#define MACH_HEADER struct mach_header_64 *
#endif
typedef const char *(*ptr)(void);
const char *hello(void) { return "hello"; }
const char *hello2(void) { return "hello2"; }
const char *hello3(void) { return "hello3"; }
const char *hello4(void) { return "hello4"; }


inline __attribute__((always_inline)) const char *inline_func(void) { return "inline_func"; }
// 将函数地址存到 mach-o __DATA 区 在运行时 从中取出 执行
// 使用 used字段，即使没有任何引用，在Release下也不会被优化
static ptr func __attribute__((used, section("__DATA" "," "__func__"))) = hello;
static ptr func2 __attribute__((used, section("__DATA" "," "__func__"))) = hello2;
static ptr func3 __attribute__((used, section("__DATA" "," "__func__"))) = hello3;
static ptr func4 __attribute__((used, section("__DATA" "," "__func__"))) = hello4;

static void load(char *section) {
    Dl_info info;
    dladdr(load, &info);
//    const MACH_HEADER mhp = _dyld_get_image_header(0);
    MACH_HEADER mhp = (MACH_HEADER)info.dli_fbase;
    unsigned long size = 0;
    uint8_t *memory = (uint8_t *)getsectiondata(mhp, "__DATA", section, &size);
    size_t itemSize = sizeof(void *);
    for(int idx = 0; idx < size / itemSize; ++idx){
        ptr func;
        memcpy(&func, memory + (idx * itemSize), itemSize);
        NSLog(@"%s", (*func)());
    }
}
int main(int argc, const char * argv[]) {
    NSLog(@"%s", inline_func());
    load("__func__");
    return 0;
}
