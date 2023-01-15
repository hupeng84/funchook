/**
 * Copyright 2023 hupeng.
 * SPDX-License-Identifier: MIT
 */

#ifndef FUNCHOOK_H_
#define FUNCHOOK_H_

#include <string.h>
#include <sys/mman.h>
#include <functional>
#include <vector>

#include <capstone/capstone.h>

template <typename R, typename... Args>
class FuncHook {
 public:
  using HookCallback = std::function<R(Args... args)>;

  FuncHook() = default;
  ~FuncHook() {
    UnHook();
    cs_close(&capstone_handle_);
  }

  void Hook(void* func, HookCallback callback, void* obj = nullptr) {
    if (func == nullptr || callback == nullptr) {
      std::cerr << "hook error!!!" << std::endl;
      return;
    }

    hook_callback = callback;
    *(getPointer()) = (uintptr_t)this;
    obj_ = obj;
    cs_open(CS_ARCH_X86, CS_MODE_64, &capstone_handle_);

    uintptr_t callback_func_addr =
        CalcCallbackFuncAddr((void*)&CallOriginalFunction);
    uintptr_t orig_func_addr = CalcOrigFuncAddr(func);
    hook_asm_size_ = SetHookAsm(orig_func_addr, callback_func_addr);
    save_sam_size_ = CalcOpecodeLength(orig_func_addr);
    orig_func_ptr_ = (void*)orig_func_addr;
    for (size_t i = 0; i < save_sam_size_; i++) {
      replace_orig_asm_.emplace_back(*((uint8_t*)orig_func_ptr_ + i));
    }
    OverrideFunc(orig_func_ptr_, replace_hook_asm_, hook_asm_size_);
  }

  HookCallback hook_callback;

 private:
  void UnHook() {
    if (orig_func_ptr_ == nullptr) {
      return;
    }
    OverrideFunc(orig_func_ptr_, replace_orig_asm_, save_sam_size_);
    orig_func_ptr_ = nullptr;
  }

  static uintptr_t* getPointer() {
    static uintptr_t saver = 0;
    return &saver;
  }

  static R CallOriginalFunction(Args... args) {
    auto this_ptr = (FuncHook*)(*getPointer());
    return this_ptr->hook_callback(args...);
  }

  void OverrideFunc(void* addr, std::vector<uint8_t>& replace, int size) {
    void* pageAddr_start = (void*)((uintptr_t)addr & 0xFFFFFFFFFFFFE000);
    void* pageAddr_end =
        (void*)((uintptr_t)((char*)addr + size) & 0xFFFFFFFFFFFFE000);
    mprotect(pageAddr_start,
             ((size_t)pageAddr_end - (size_t)pageAddr_start) + 0x2000,
             PROT_READ | PROT_WRITE | PROT_EXEC);
    memcpy(addr, &replace[0], size);
  }

  int CalcOpecodeLength(uintptr_t code) {
    int len = 0;
    cs_insn* insn;
    auto count = cs_disasm(capstone_handle_, (uint8_t*)code,
                           hook_asm_size_ + 16, 0, 0, &insn);
    if (count > 0) {
      for (size_t i = 0; i < count; i++) {
        len += insn[i].size;
        if (len >= hook_asm_size_) {
          break;
        }
      }
    }

    cs_free(insn, count);
    return len;
  }

  uintptr_t CalcCallbackFuncAddr(void* callback) {
    if (*((unsigned char*)callback) == 0xe9) {
      uintptr_t jmp_addr = *((int32_t*)((unsigned char*)callback + 1));
      return (uintptr_t)callback + jmp_addr + 5;
    }
    return (uintptr_t)callback;
  }

  int SetHookAsm(uintptr_t orig_func_addr, uintptr_t hook_func_addr) {
    if (hook_func_addr - orig_func_addr < 0x80000000) {
      // 0xe9 00 00 00 00
      replace_hook_asm_.emplace_back(0xe9);
      uint32_t addr = (uint32_t)(hook_func_addr - orig_func_addr - 5);
      replace_hook_asm_.emplace_back((uint8_t)(addr));
      replace_hook_asm_.emplace_back((uint8_t)(addr >> 8));
      replace_hook_asm_.emplace_back((uint8_t)(addr >> 16));
      replace_hook_asm_.emplace_back((uint8_t)(addr >> 24));
      return 5;
    } else {
      replace_hook_asm_.emplace_back(0x68);
      uint32_t addr = (uint32_t)(0x00000000ffffffff & hook_func_addr);
      replace_hook_asm_.emplace_back((uint8_t)(addr));
      replace_hook_asm_.emplace_back((uint8_t)(addr >> 8));
      replace_hook_asm_.emplace_back((uint8_t)(addr >> 16));
      replace_hook_asm_.emplace_back((uint8_t)(addr >> 24));
      replace_hook_asm_.emplace_back(0xc7);
      replace_hook_asm_.emplace_back(0x44);
      replace_hook_asm_.emplace_back(0x24);
      replace_hook_asm_.emplace_back(0x04);
      addr = hook_func_addr >> 32;
      replace_hook_asm_.emplace_back((uint8_t)(addr));
      replace_hook_asm_.emplace_back((uint8_t)(addr >> 8));
      replace_hook_asm_.emplace_back((uint8_t)(addr >> 16));
      replace_hook_asm_.emplace_back((uint8_t)(addr >> 24));
      replace_hook_asm_.emplace_back(0xc3);
      return 14;
    }
  }

  uintptr_t CalcOrigFuncAddr(void* func) {
    if ((uintptr_t)func < 100) {
      if (obj_ == nullptr) {
        exit(-1);
      }
      uintptr_t* vtable = (uintptr_t*)(*((uintptr_t*)func));
      uintptr_t index = ((uintptr_t)func - 1) / sizeof(void*);
      func = (void*)(vtable[index]);
    }

    uintptr_t override_addr = 0;
    if (*((unsigned char*)func + 0) == 0xe9) {
      // 0xe9 call
      uintptr_t jmpaddress = *((int32_t*)((unsigned char*)func + 1));
      override_addr = (((uintptr_t)func) + jmpaddress) + 5;  //+5 e9 00 00 00 00
    } else {
      override_addr = (uintptr_t)func;
    }

    uintptr_t vcall_addr = CalcVCall(override_addr);
    return vcall_addr == 0 ? override_addr : vcall_addr;
  }

  uintptr_t CalcVCall(uintptr_t override_addr) {
    int vcall_head = 0;
    auto addr = (unsigned char*)override_addr;
    if (*addr == 0x48) {
      addr++;
      vcall_head = 4;
    }
    if (*addr == 0x8B && *(addr + 1) == 0x01 && *(addr + 2) == 0xFF) {
      if (vcall_head == 0)
        vcall_head == 3;
      addr += 3;
    } else {
      return 0;
    }

    if (obj_ == nullptr) {
      exit(-1);
    }

    int plus_addr = 0;
    if (*addr == 0x60) {
      plus_addr = (int)*(addr + 1);
    } else if (*addr != 0x20) {
      exit(-1);
    }

    plus_addr = plus_addr / sizeof(void*);
    override_addr = (uintptr_t) * ((void**)*((void***)obj_) + plus_addr);
    if (*((unsigned char*)override_addr + 0) == 0xe9) {
      uintptr_t jmp_address = *((int32_t*)((unsigned char*)override_addr + 1));
      override_addr += jmp_address;
      override_addr += 5;  // e9 00 00 00 00;
    }
    return override_addr;
  }

  void* orig_func_ptr_ = nullptr;
  void* obj_ = nullptr;
  std::vector<uint8_t> replace_orig_asm_;
  std::vector<uint8_t> replace_hook_asm_;
  int hook_asm_size_;
  int save_sam_size_;
  csh capstone_handle_;
  FuncHook(const FuncHook&) = delete;
  FuncHook& operator=(const FuncHook&) = delete;
};

#endif
