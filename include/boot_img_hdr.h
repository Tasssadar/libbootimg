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
#define BOOT_NAME_SIZE 16
#define BOOT_ARGS_SIZE 512

#define BOOT_MAGIC_ELF "ELF"
#define BOOT_MAGIC_ELF_SIZE 3
#define VER_ELF_1 (1 << 0)
#define VER_ELF_2 (1 << 1)

#define OUT_ELF (1 << 0)  /* Same output format: ELF container */
#define OUT_AND (1 << 1)  /* Different output format: standard Android container */

#define ELF_PROG_KER 0
#define ELF_PROG_RAM 1
#define ELF_PROG_RPM 2
#define ELF_PROG_CMD 3

#define ELF_SECT_CMD 0

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

struct boot_img_elf_hdr
{
    /* Global structure of the Sony ELF header - Respective usual values:  | 8960       | 8974       | */
    uint8_t magic[8];               /* .ELF (0x00 to 0x07)                 | .ELF...    | .ELF...    | */
    uint8_t unused[8];              /* unused chars (0x08 to 0x0F)         | 0x00       | 0x00       | */
    uint16_t type;                  /* boot type (0x10 to 0x11)            | 0x02       | 0x02       | */
    uint16_t machine;               /* boot machine (0x12 to 0x13)         | 0x28       | 0x28       | */
    uint32_t version;               /* boot version (0x14 to 0x17)         | 0x01       | 0x01       | */
    uint32_t entry_addr;            /* boot entry (0x18 to 0x1B)           | 0x80208000 | 0x00008000 | */
    uint32_t phoff;                 /* boot phoff (0x1C to 0x1F)           | 0x34       | 0x34       | */
    uint32_t shoff;                 /* boot shoff (0x20 to 0x23)           | 0x00000000 | 0x00B3.... | */
    uint32_t flags;                 /* boot flags (0x24 to 0x27)           | 0x00       | 0x00       | */
    uint16_t ehsize;                /* boot ehsize (0x28 to 0x29)          | 0x34       | 0x34       | */
    uint16_t phentsize;             /* boot phentsize (0x2A to 0x2B)       | 0x20       | 0x20       | */
    uint16_t phnum;                 /* boot phnum (0x2C to 0x2D)           | 0x05/0x04  | 0x03       | */
    uint16_t shentsize;             /* boot shentsize (0x2E to 0x2F)       | 0x00       | 0x28       | */
    uint16_t shnum;                 /* boot shnum (0x30 to 0x31)           | 0x00       | 0x01       | */
    uint16_t shstrndx;              /* boot shstrndx (0x32 to 0x33)        | 0x00       | 0x00       | */
};

struct boot_img_elf_info
{
    struct boot_img_elf_hdr hdr;        /* The ELF file header. */
    struct boot_img_elf_prog_hdr* prog; /* The program header entries. */
    struct boot_img_elf_sect_hdr* sect; /* The section header entries. */
    struct boot_img_elf_misc_hdr* misc; /* Miscellaneous information found in some ELF versions. */
    uint8_t elf_version;
    uint8_t elf_out_format;
    uint32_t cmdline_size;
    uint8_t cmdline_metadata[8];
    uint32_t cmdline_metadata_cnt;
    uint8_t* cmdline_signature;
    uint32_t cmdline_signature_cnt;
};

struct boot_img_elf_prog_hdr
{
    uint32_t type;              /* type (position + 0x0 to 0x3) */
    uint32_t offset;            /* offset (position + 0x4 to 0x7) */
    uint32_t vaddr;             /* address (position + 0x8 to 0xB) */
    uint32_t paddr;             /* address duplicate (position + 0xC to 0xF) */
    uint32_t size;              /* size (position + 0x10 to 0x13) */
    uint32_t msize;             /* size duplicate (position + 0x14 to 0x17) */
    uint32_t flags;             /* flags (position + 0x18 to 0x1B) */
    uint32_t align;             /* alignment (position + 0x1C to 0x1F)*/
};

struct boot_img_elf_sect_hdr
{
    uint32_t name;
    uint32_t type;
    uint32_t flags;
    uint32_t addr;
    uint32_t offset;
    uint32_t size;
    uint8_t misc[16];
};

struct boot_img_elf_misc_hdr
{
    uint8_t* data;                  /* header additional data */
    uint32_t data_size;             /* header additional size */
    uint8_t name[BOOT_NAME_SIZE];   /* added - asciiz product name */
};

#endif
