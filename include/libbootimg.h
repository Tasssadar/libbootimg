#ifndef LIBBOOTIMG_H
#define LIBBOOTIMG_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "boot_img_hdr.h"

#define LIBBOOTIMG_VERSION 0x000106 // 0xMMNNPP
#define LIBBOOTIMG_VERSION_STR "0.1.6"

struct bootimg
{
    struct boot_img_hdr hdr;
    uint8_t *kernel;
    uint8_t *ramdisk;
    uint8_t *second;
    uint32_t size;
    int size_is_max_only;
};

void libbootimg_init_new(struct bootimg *img);
int libbootimg_init_load(struct bootimg *img, const char *path);
int libbootimg_init_load_parts(struct bootimg *img, const char *path,
                               int load_kernel, int load_rd, int load_second);
void libbootimg_destroy(struct bootimg *b);
int libbootimg_load_header(struct boot_img_hdr *hdr, const char *path);

int libbootimg_dump_kernel(struct bootimg *b, const char *dest);
int libbootimg_dump_ramdisk(struct bootimg *b, const char *dest);
int libbootimg_dump_second(struct bootimg *b, const char *dest);
int libbootimg_dump(struct bootimg *b, const char *dest_dir);

int libbootimg_load_kernel(struct bootimg *b, const char *src);
int libbootimg_load_ramdisk(struct bootimg *b, const char *src);
int libbootimg_load_second(struct bootimg *b, const char *src);

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
