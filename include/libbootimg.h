/**
 * @file
 * @brief This file contains all public libbootimg methods, defines and structs
 */
#ifndef LIBBOOTIMG_H
#define LIBBOOTIMG_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdio.h>
#include "boot_img_hdr.h"

#define LIBBOOTIMG_VERSION 0x000200 // 0xMMNNPP
#define LIBBOOTIMG_VERSION_STR "0.2.0"

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
    struct bootimg_blob blobs[LIBBOOTIMG_BLOB_CNT]; /*!< Blobs packed in the boot image. */
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
 * @return zero if successful, negative value from libbootimg_error if failed.
 */
int libbootimg_load_header(struct boot_img_hdr *hdr, const char *path);

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
 * Writes boot image to a file and then calls libbootimg_destroy.
 * The bootimg struct is destroyed even if this function fails.
 * @param b pointer to struct bootimg
 * @param dest path to destination file
 * @return number of bytes written to the file if successful, negative value from libbootimg_error if failed.
 */
int libbootimg_write_img_and_destroy(struct bootimg *b, const char *dest);


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

#ifdef __cplusplus
}
#endif

#endif
