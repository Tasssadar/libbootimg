/**
 * @file
 * @brief This file contains all public libbootimg methods, defines and structs
 */
#ifndef LIBBOOTIMG_H
#define LIBBOOTIMG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdio.h>
#include <cutils/klog.h>
#include "boot_img_hdr.h"

#define LIBBOOTIMG_VERSION 0x000203 // 0xMMNNPP
#define LIBBOOTIMG_VERSION_STR "0.2.3"

#ifdef DEBUG_KMSG
#define LOG_DBG(fmt, ...) klog_write(3, "<3>%s: " fmt, "libbootimg", ##__VA_ARGS__)
#elif DEBUG_STDOUT
#define LOG_DBG printf("libbootimg: "); printf
#else
#define LOG_DBG(fmt, ...) ""
#endif

#define ARCH_32_BITS 0
#define ARCH_64_BITS 1

/**
 * Enum containing possible blob types in a boot image.
 */
enum libbootimg_blob_type
{
    LIBBOOTIMG_BLOB_KERNEL  = 0,
    LIBBOOTIMG_BLOB_RAMDISK = 1,
    LIBBOOTIMG_BLOB_SECOND  = 2,
    LIBBOOTIMG_BLOB_DTB     = 3,

    LIBBOOTIMG_BLOB_CNT
};

/**
 * Enum with masks passed to libbootimg_init_load method.
 * Specifies which parts of boot image to load from disk.
 */
enum libbootimg_blob_load_mask
{
    LIBBOOTIMG_LOAD_HDR_ONLY    = 0x00,

    LIBBOOTIMG_LOAD_KERNEL      = (1 << LIBBOOTIMG_BLOB_KERNEL),
    LIBBOOTIMG_LOAD_RAMDISK     = (1 << LIBBOOTIMG_BLOB_RAMDISK),
    LIBBOOTIMG_LOAD_SECOND      = (1 << LIBBOOTIMG_BLOB_SECOND),
    LIBBOOTIMG_LOAD_DTB         = (1 << LIBBOOTIMG_BLOB_DTB),

    LIBBOOTIMG_LOAD_ALL         = ( LIBBOOTIMG_LOAD_KERNEL |
                                    LIBBOOTIMG_LOAD_RAMDISK |
                                    LIBBOOTIMG_LOAD_SECOND |
                                    LIBBOOTIMG_LOAD_DTB )
};

/**
 * Enum with all possible error return values.
 */
// Keep libbootimg_error_str updated!
enum libbootimg_error
{
    LIBBOOTIMG_SUCCESS                  =  0,
    LIBBOOTIMG_ERROR_IO                 = -1,
    LIBBOOTIMG_ERROR_ACCESS             = -2,
    LIBBOOTIMG_ERROR_NOT_FOUND          = -3,
    LIBBOOTIMG_ERROR_INVALID_MAGIC      = -4,
    LIBBOOTIMG_ERROR_IMG_EOF            = -5,
    LIBBOOTIMG_ERROR_NO_BLOB_DATA       = -6,
    LIBBOOTIMG_ERROR_FILE_TOO_BIG       = -7,
    LIBBOOTIMG_ERROR_MISSING_BLOB       = -8,
    LIBBOOTIMG_ERROR_INVALID_PAGESIZE   = -9,

    LIBBOOTIMG_ERROR_OTHER              = -128
};

/**
 * One data blob from boot image.
 */
struct bootimg_blob
{
    uint8_t *data;
    uint32_t *size; /*!< Pointer to size of this blob in struct boot_img_hdr. Never change the address this is pointing to! */
};

/**
 * Main libbootimg struct with all data.
 * You will use this struct to work with libbootimg.
 */
struct bootimg
{
    struct boot_img_hdr hdr; /*!< Boot image header */
    struct bootimg_blob blob; /* Complete blob */
    uint32_t blob_size; /* Size of the complete blob */
    struct bootimg_blob blobs[LIBBOOTIMG_BLOB_CNT]; /*!< Blobs packed in the boot image */
    int start_offset; /*!< Offset of the boot image structure from the start of the file. Only used when loading blobs from boot.img file */
    uint8_t is_elf; /*!< Select the ELF boot image format */
    struct boot_img_elf_info* hdr_info; /*!< Boot image meta-information for ELF formats */
};

/**
 * Initializes the struct bootimg and leaves it empty with some default values.
 * It fills in the magic and default pagesize in struct boot_img_hdr.
 * @see struct boot_img_hdr
 * @param img pointer to (uninitialized) struct bootimg
 */
void libbootimg_init_new(struct bootimg *img);

/**
 * Initializes the struct bootimg and loads data into it.
 * @param img pointer to (uninitialized) struct bootimg
 * @param path path to boot.img to load data from
 * @param load_blob_mask mask specifying which parts to load into the bootimg struct
 * @see enum libbootimg_blob_load_mask
 * @return Zero if successful, negative value from libbootimg_error if failed.
 */
int libbootimg_init_load(struct bootimg *img, const char *path, int load_blob_mask);

/**
 * Loads boot_img_hdr from file on disk
 * @param hdr pointer to boot_img_hdr structure
 * @param path path to boot.img to load header from
 * @return positive offset of the header from the start of the file if
 *         successful, negative value from libbootimg_error if failed.
 */
int libbootimg_load_header(struct boot_img_hdr *hdr, const char *path);

/**
 * Determines the ELF boot image version (custom definition) and the
 * required output format (ELF or ANDROID!) based on the number of
 * program headers given by the ELF header.
 * @param hdr_info pointer to the structure holding the read header information
 */
void libbootimg_get_elf_version(struct boot_img_elf_info *hdr_info);

/**
 * Reads the image header from the given ELF file and adds the content
 * to the given structure, adapting 32 bits to 64 bits if needed.
 * @param hdr_info structure holding the meta-information of the given ELF file
 * @param f pointer to the file descriptor of the ELF file
 * @return zero on success or the error code returned by the file operations.
 */
int libbootimg_load_elf_header(struct boot_img_elf_info *hdr_info, FILE *f);

/**
 * Reads the program headers from the given ELF file and adds the content
 * of each header to the given structure.
 * @param hdr_info structure holding the meta-information of the given ELF file
 * @param f pointer to the file descriptor of the ELF file
 * @return zero on success or the error code returned by the file operations.
 */
int libbootimg_load_elf_prog_header(struct boot_img_elf_info *hdr_info, FILE *f);

/**
 * Reads the section headers from the given ELF file and adds the content
 * of each header to the given structure.
 * @param hdr_info structure holding the meta-information of the given ELF file
 * @param f pointer to the file descriptor of the ELF file
 * @return zero on success or the error code returned by the file operations.
 */
int libbootimg_load_elf_sect_header(struct boot_img_elf_info *hdr_info, FILE *f);

/**
 * Reads the miscellaneous information from the given ELF file and adds the content
 * to the given structure. This information is present in some ELF versions and
 * required for them to operate properly (version 1).
 * @param hdr_info structure holding the meta-information of the given ELF file
 * @param size of the bootimage pagesize needed for alignment
 * @param f pointer to the file descriptor of the ELF file
 * @return one on success or the error code returned by the file operations.
 */
int libbootimg_load_elf_misc_header(struct boot_img_elf_info *hdr_info, uint32_t page_size, FILE *f);

/**
 * Extracts the kernel boot command line from an ELF file and adds it to
 * the generic structure describing the blob (-> hdr).
 * @param hdr pointer to boot_img_hdr structure
 * @param elf_info structure holding the meta-information of the given ELF file.
 * @param f pointer to the file descriptor of the ELF file.
 */
void libbootimg_read_cmdline(struct boot_img_hdr *hdr, struct boot_img_elf_info *elf_info, FILE *f);

/**
 * Returns a pointer referencing the ELF program header which describes the content
 * of a given type like the kernel or ramdisk part of a boot image.
 * @param hdr_info structure holding the meta-information of the given ELF file.
 * @param type integer value that describes the desired pointer as given in the enum
 * 			{@link libbootimg_blob_type}.
 * @return pointer to the program header describing the desired part of the boot image.
 */
struct boot_img_elf_prog_hdr* get_elf_proc_hdr_of(struct boot_img_elf_info *elf_info, int type);

/**
 * Loads boot_img_hdr or boot_img_hdr_elf from file on disk
 * @param hdr pointer to boot_img_hdr structure
 * @param hdr_elf pointer to boot_img_hdr_elf structure
 * @param is_elf pointer to is_elf attribute
 * @param path path to boot.img to load header from
 * @return positive offset of the header from the start of the file if
 *         successful, negative value from libbootimg_error if failed.
 */
int libbootimg_load_headers(struct boot_img_hdr *hdr,
        struct boot_img_elf_info *hdr_elf, uint8_t *is_elf, const char *path);

/**
 * Updates the header addresses to the blobs.
 * @param img pointer to initialized struct bootimg
 * @return Zero if successful, negative value from libbootimg_error if failed.
 */
int libbootimg_update_headers(struct bootimg *b);

/**
 * Frees all resources used by this bootimg struct
 * @param b pointer to struct bootimg
 */
void libbootimg_destroy(struct bootimg *b);

/**
 * Writes blob to a file.
 * @param blob pointer to source struct bootimg_blob
 * @param dest path to destination file
 * @return zero if successful, negative value from libbootimg_error if failed.
 */
int libbootimg_dump_blob(struct bootimg_blob *blob, const char *dest);

/**
 * Writes kernel blob to a file.
 * @param b pointer to struct bootimg
 * @param dest path to destination file
 * @return zero if successful, negative value from libbootimg_error if failed.
 */
int libbootimg_dump_kernel(struct bootimg *b, const char *dest);

/**
 * Writes ramdisk blob to a file.
 * @param b pointer to struct bootimg
 * @param dest path to destination file
 * @return zero if successful, negative value from libbootimg_error if failed.
 */
int libbootimg_dump_ramdisk(struct bootimg *b, const char *dest);

/**
 * Writes second stage blob to a file.
 * @param b pointer to struct bootimg
 * @param dest path to destination file
 * @return zero if successful, negative value from libbootimg_error if failed.
 */
int libbootimg_dump_second(struct bootimg *b, const char *dest);

/**
 * Writes DTB blob to a file.
 * @param b pointer to struct bootimg
 * @param dest path to destination file
 * @return zero if successful, negative value from libbootimg_error if failed.
 */
int libbootimg_dump_dtb(struct bootimg *b, const char *dest);



/**
 * Loads blob data from a file.
 * @param blob pointer to dest struct bootimg_blob
 * @param src path to source file
 * @return zero if successful, negative value from libbootimg_error if failed.
 */
int libbootimg_load_blob(struct bootimg_blob *blob, const char *src);

/**
 * Loads kernel blob data from a file.
 * @param b pointer to struct bootimg
 * @param src path to source file
 * @return zero if successful, negative value from libbootimg_error if failed.
 */
int libbootimg_load_kernel(struct bootimg *b, const char *src);

/**
 * Loads ramdisk blob data from a file.
 * @param b pointer to struct bootimg
 * @param src path to source file
 * @return zero if successful, negative value from libbootimg_error if failed.
 */
int libbootimg_load_ramdisk(struct bootimg *b, const char *src);

/**
 * Loads second stage blob data from a file.
 * @param b pointer to struct bootimg
 * @param src path to source file
 * @return zero if successful, negative value from libbootimg_error if failed.
 */
int libbootimg_load_second(struct bootimg *b, const char *src);

/**
 * Loads DTB blob data from a file.
 * @param b pointer to struct bootimg
 * @param src path to source file
 * @return zero if successful, negative value from libbootimg_error if failed.
 */
int libbootimg_load_dtb(struct bootimg *b, const char *src);



/**
 * Writes boot image to a file
 * @param b pointer to struct bootimg
 * @param dest path to destination file
 * @return number of bytes written to the file if successful, negative value from libbootimg_error if failed.
 */
int libbootimg_write_img(struct bootimg *b, const char *dest);

/**
 * Writes boot image to a file
 * @param b pointer to struct bootimg
 * @param f pointer to FILE to write data into
 * @return number of bytes written to the file if successful, negative value from libbootimg_error if failed.
 */
int libbootimg_write_img_fileptr(struct bootimg *b, FILE *f);

/**
 * Writes boot image to a file: Updated implementation that effectively *injects* data into an existing boot image
 * @param b pointer to struct bootimg
 * @param f pointer to FILE to write data into
 * @return number of bytes written to the file if successful, negative value from libbootimg_error if failed.
 */
int libbootimg_write_img_fileptr_new(struct bootimg *b, FILE *f);

/**
 * Writes boot image to a file and then calls libbootimg_destroy.
 * The bootimg struct is destroyed even if this function fails.
 * @param b pointer to struct bootimg
 * @param dest path to destination file
 * @return number of bytes written to the file if successful, negative value from libbootimg_error if failed.
 */
int libbootimg_write_img_and_destroy(struct bootimg *b, const char *dest);

/**
 * Returns architecture type, 32bits or 64bits
 * @return architecture identification ARCH_32_BITS or ARCH_64_BITS
 */
uint8_t libbootimg_architecture(void);

/**
 * Returns version number, format is 0xMMNNPP, so for version 0.1.12 it would return 0x000112
 * @return version number in 0xMMNNPP format
 */
uint32_t libbootimg_version(void);

/**
 * Returns version string
 * @return version string, e.g. 0.1.12
 */
const char *libbootimg_version_str(void);

/**
 * Translates value from enum libbootimg_error to readable string.
 * @param error value from libbootimg_error
 * @see enum libbootimg_error
 * @return readable error string
 */
const char *libbootimg_error_str(int error);

/**
 * Prints the content of the boot image information to the stdout or
 * the kernel log (dmesg).
 * @param hdr pointer to the boot image information.
 */
void print_hdr_to_log(struct boot_img_hdr* hdr);

/**
 * Prints the content of an elf header described by the given structure
 * to the stdout or the kernel log (dmesg).
 * @param elf_info pointer to the elf header information.
 */
void print_elf_hdr_to_log(struct boot_img_elf_info* elf_info);

/**
 * Prints the content of an elf program header described by the given structure
 * to the stdout or the kernel log (dmesg).
 * @param elf_prog_hdr pointer to the program header information.
 */
void print_elf_prog_hdr_to_log(struct boot_img_elf_prog_hdr* elf_prog_hdr);

/**
 * Prints the content of an elf section header described by the given structure
 * to the stdout or the kernel log (dmesg).
 * @param elf_sect_hdr pointer to the section header information.
 */
void print_elf_sect_hdr_to_log(struct boot_img_elf_sect_hdr* elf_sect_hdr);

/**
 * Prints the content of an elf misc header described by the given structure
 * to the stdout or the kernel log (dmesg).
 * @param elf_sect_hdr pointer to the section header information.
 */
void print_elf_misc_hdr_to_log(struct boot_img_elf_misc_hdr* elf_misc_hdr);

#ifdef __cplusplus
}
#endif

#endif
