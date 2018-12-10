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
#import <mach-o/loader.h>

#ifndef __LP64__
#define MACH_HEADER struct mach_header *
#define MACH_O_SECTION_DATA_SIZE uint32_t
#else
#define MACH_HEADER struct mach_header_64 *
#define MACH_O_SECTION_DATA_SIZE uint64_t
#endif
typedef const char *(*ptr)(void);
const char *hello(void) { return "hello"; }
const char *hello2(void) { return "hello2"; }
const char *hello3(void) { return "hello3"; }
const char *hello4(void) { return "hello4"; }

typedef struct {
    char *key;
    ptr func;
} _FUNC_DATA;


inline __attribute__((always_inline)) const char *inline_func(void) { return "inline_func"; }
// 将函数地址存到 mach-o __DATA 区 在运行时 从中取出 执行
// 使用 used字段，即使没有任何引用，在Release下也不会被优化
static _FUNC_DATA _data_1 __attribute__((used, section("__DATA" "," "__func__"))) = (_FUNC_DATA){"hello", hello};
static _FUNC_DATA _data_2 __attribute__((used, section("__DATA" "," "__func__"))) = (_FUNC_DATA){"hello", hello2};
static _FUNC_DATA _data_3 __attribute__((used, section("__DATA" "," "__func__"))) = (_FUNC_DATA){"hello", hello3};
static _FUNC_DATA _data_4 __attribute__((used, section("__DATA" "," "__func__"))) = (_FUNC_DATA){"hello", hello4};

//static ptr func __attribute__((used, section("__DATA" "," "__func__"))) = hello;
//static ptr func2 __attribute__((used, section("__DATA" "," "__func__"))) = hello2;
//static ptr func3 __attribute__((used, section("__DATA" "," "__func__"))) = hello3;
//static ptr func4 __attribute__((used, section("__DATA" "," "__func__"))) = hello4;

static void load(const char *section, const char *key) {
    const MACH_HEADER mhp = NULL;
    
//    {
//        Dl_info info;
//        dladdr(load, &info);
//        mhp = (MACH_HEADER)info.dli_fbase;
//    }
    
    {
        uint32_t imageCount = _dyld_image_count();
        for (uint32_t i = 0; i < imageCount; i++) {
            const struct mach_header *header = _dyld_get_image_header(i);
            if (header->filetype == MH_EXECUTE) {
                mhp = (MACH_HEADER)header;
                break;
            }
        }
    }
    
    unsigned long size = 0;
    uint8_t *memory = getsectiondata(mhp, "__DATA", section, &size);
    size_t itemSize = sizeof(_FUNC_DATA);
    for(int idx = 0; idx < size / itemSize; ++idx){
        _FUNC_DATA *func = (_FUNC_DATA *)(memory + (idx * itemSize));
//        ptr *func = (ptr *)(memory + (idx * itemSize));
//        memcpy(&func, memory + (idx * itemSize), itemSize);
//        if (func != NULL && *func != NULL) {
//            NSLog(@"%s", (*func)());
//        }
        if (func != NULL
            && func->key != NULL
            && func->func != NULL
            && strcmp(func->key, key) == 0) {
            NSLog(@"%s", func->func());
        }
    }
}
int main(int argc, const char * argv[]) {
    NSLog(@"%s", inline_func());
    load("__func__", "hello");
    return 0;
}
