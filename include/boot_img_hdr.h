/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef BOOT_IMG_HDR_H
#define BOOT_IMG_HDR_H

#include <stdint.h>

/*
** +-----------------+ 
** | boot header     | 1 page
** +-----------------+
** | kernel          | n pages
** +-----------------+
** | ramdisk         | m pages
** +-----------------+
** | second stage    | o pages
** +-----------------+
** | device tree     | p pages
** +-----------------+
**
** n = (kernel_size + page_size - 1) / page_size
** m = (ramdisk_size + page_size - 1) / page_size
** o = (second_size + page_size - 1) / page_size
** p = (dt_size + page_size - 1) / page_size
**
** 0. all entities are page_size aligned in flash
** 1. kernel and ramdisk are required (size != 0)
** 2. second is optional (second_size == 0 -> no second)
** 3. load each element (kernel, ramdisk, second) at
**    the specified physical address (kernel_addr, etc)
** 4. prepare tags at tag_addr.  kernel_args[] is
**    appended to the kernel commandline in the tags.
** 5. r0 = 0, r1 = MACHINE_TYPE, r2 = tags_addr
** 6. if second_size != 0: jump to second_addr
**    else: jump to kernel_addr
*/

#define BOOT_MAGIC "ANDROID!"
#define BOOT_MAGIC_SIZE 8
#define BOOT_MAGIC_ELF "ELF"
#define BOOT_MAGIC_ELF_SIZE 3
#define BOOT_NAME_SIZE 16
#define BOOT_ARGS_SIZE 512

struct boot_img_hdr
{
    uint8_t magic[BOOT_MAGIC_SIZE];

    uint32_t kernel_size;  /* size in bytes */
    uint32_t kernel_addr;  /* physical load addr */

    uint32_t ramdisk_size; /* size in bytes */
    uint32_t ramdisk_addr; /* physical load addr */

    uint32_t second_size;  /* size in bytes */
    uint32_t second_addr;  /* physical load addr */

    uint32_t tags_addr;    /* physical addr for kernel tags */
    uint32_t page_size;    /* flash page size we assume */
    uint32_t dt_size;      /* device tree in bytes */
    uint32_t unused;       /* future expansion: should be 0 */

    uint8_t name[BOOT_NAME_SIZE]; /* asciiz product name */

    uint8_t cmdline[BOOT_ARGS_SIZE];

    uint32_t id[8]; /* timestamp / checksum / sha1 / etc */
};

struct boot_img_hdr_elf
{
    uint8_t magic[8];               /* .ELF (0x00 to 0x07) */
    uint8_t unused[8];              /* unused chars */
    uint16_t type;                  /* boot type */
    uint16_t machine;               /* boot machine */
    uint32_t version;               /* boot version */
    uint32_t entry_addr;            /* boot entry */
    uint32_t phoff;                 /* boot phoff */
    uint32_t shoff;                 /* boot shoff */
    uint32_t flags;                 /* boot flags */
    uint16_t ehsize;                /* boot ehsize */
    uint16_t phentsize;             /* boot phentsize */
    uint16_t phnum;                 /* boot phnum */
    uint16_t shentsize;             /* boot shentsize */
    uint16_t shnum;                 /* boot shnum */
    uint16_t shstrndx;              /* boot shstrndx */
    uint32_t kernel_type;           /* kernel type (0x34 to 0x37) */
    uint32_t kernel_offset;         /* kernel offset (0x38 to 0x3B) */
    uint32_t kernel_vaddr;          /* kernel address (0x3C to 0x3F) */
    uint32_t kernel_paddr;          /* kernel address duplicate */
    uint32_t kernel_size;           /* kernel size (0x44 to 0x47) */
    uint32_t kernel_msize;          /* kernel size duplicate */
    uint32_t kernel_flags;          /* kernel flags (0x4C to 0x4F) */
    uint32_t kernel_align;          /* kernel alignment */
    uint32_t ramdisk_type;          /* kernel type (0x54) */
    uint32_t ramdisk_offset;        /* ramdisk offset (0x58 to 0x5B) */
    uint32_t ramdisk_vaddr;         /* ramdisk address (0x5C to 0x5F) */
    uint32_t ramdisk_paddr;         /* ramdisk address duplicate */
    uint32_t ramdisk_size;          /* ramdisk size (0x64 to 0x67) */
    uint32_t ramdisk_msize;         /* ramdisk size duplicate */
    uint32_t ramdisk_flags;         /* ramdisk flags (0x6C to 0x6F) */
    uint32_t ramdisk_align;         /* cmdline alignment */
    uint32_t rpm_type;              /* rpm type (0x74 to 0x77) */
    uint32_t rpm_offset;            /* rpm offset (0x78 to 0x7B) */
    uint32_t rpm_vaddr;             /* rpm address (0x7C to 0x7F) */
    uint32_t rpm_paddr;             /* rpm address duplicate */
    uint32_t rpm_size;              /* rpm size (0x84 to 0x87) */
    uint32_t rpm_msize;             /* rpm size duplicate */
    uint32_t rpm_flags;             /* rpm flags (0x8C to 0x8F) */
    uint32_t rpm_align;             /* rpm alignment */
    uint32_t cmd_type;              /* cmdline type (0x94 to 0x97) */
    uint32_t cmd_offset;            /* cmdline offset (0x98 to 0x9B) */
    uint32_t cmd_vaddr;             /* cmdline address (0x9C to 0x9F) */
    uint32_t cmd_paddr;             /* cmdline address duplicate */
    uint32_t cmd_size;              /* cmdline size (0xA4 to 0xA7) */
    uint32_t cmd_msize;             /* cmdline size duplicate */
    uint32_t cmd_flags;             /* cmdline flags (0xAC to 0xAF) */
    uint32_t cmd_align;             /* cmdline alignment */
    uint8_t header_vals[3900];      /* header additional values */
    uint8_t name[BOOT_NAME_SIZE];   /* added - asciiz product name */
};

typedef struct boot_img_hdr boot_img_hdr;

#endif
