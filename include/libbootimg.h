#ifndef LIBBOOTIMG_H
#define LIBBOOTIMG_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "boot_img_hdr.h"

#define LIBBOOTIMG_VERSION 0x000112 // 0xMMNNPP
#define LIBBOOTIMG_VERSION_STR "0.1.12"

enum
{
    LIBBOOTIMG_BLOB_KERNEL  = 0,
    LIBBOOTIMG_BLOB_RAMDISK = 1,
    LIBBOOTIMG_BLOB_SECOND  = 2,
    LIBBOOTIMG_BLOB_DTB     = 3,

    LIBBOOTIMG_BLOB_CNT
};

struct bootimg_blob
{
    uint8_t **data;
    uint32_t *size;
};

struct bootimg
{
    struct boot_img_hdr hdr;
    uint8_t *kernel;
    uint8_t *ramdisk;
    uint8_t *second;
    uint8_t *dtb;
    uint32_t size;
    int size_is_max_only;

    struct bootimg_blob *blobs;
};

// for libbootimg_load_parts
enum
{
    LIBBOOTIMG_LOAD_ONLY_HDR = 0x00,

    LIBBOOTIMG_LOAD_KERNEL  = (1 << LIBBOOTIMG_BLOB_KERNEL),
    LIBBOOTIMG_LOAD_RAMDISK = (1 << LIBBOOTIMG_BLOB_RAMDISK),
    LIBBOOTIMG_LOAD_SECOND  = (1 << LIBBOOTIMG_BLOB_SECOND),
    LIBBOOTIMG_LOAD_DTB     = (1 << LIBBOOTIMG_BLOB_DTB),

    LIBBOOTIMG_LOAD_ALL     = 0xFFFFFFFF
};

void libbootimg_init_new(struct bootimg *img);
void libbootimg_init_blob_table(struct bootimg *img);
int libbootimg_init_load(struct bootimg *img, const char *path);
int libbootimg_init_load_parts(struct bootimg *img, const char *path, int load_blob_mask);
int libbootimg_load_header(struct boot_img_hdr *hdr, const char *path);
void libbootimg_destroy(struct bootimg *b);

int libbootimg_dump_kernel(struct bootimg *b, const char *dest);
int libbootimg_dump_ramdisk(struct bootimg *b, const char *dest);
int libbootimg_dump_second(struct bootimg *b, const char *dest);
int libbootimg_dump_dtb(struct bootimg *b, const char *dest);
int libbootimg_dump(struct bootimg *b, const char *dest_dir);

int libbootimg_load_kernel(struct bootimg *b, const char *src);
int libbootimg_load_ramdisk(struct bootimg *b, const char *src);
int libbootimg_load_second(struct bootimg *b, const char *src);
int libbootimg_load_dtb(struct bootimg *b, const char *src);

int libbootimg_write_img(struct bootimg *b, const char *dest);
int libbootimg_write_img_and_destroy(struct bootimg *b, const char *dest);

int libbootimg_load_config(struct bootimg *b, const char *src, int *error_line);
int libbootimg_load_config_line(struct bootimg *b, char *line);
int libbootimg_write_config(struct bootimg *b, const char *dst);

uint32_t libbootimg_version(void);
const char *libbootimg_version_str(void);

#ifdef __cplusplus
}
#endif

#endif
