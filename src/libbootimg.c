#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>

#include "../include/libbootimg.h"

#define DEFAULT_PAGE_SIZE 2048
#define MAX_PATH_LEN 4096

static inline unsigned align_size(unsigned size, unsigned page_size)
{
    return ((size + page_size - 1)/page_size)*page_size;
}

void libbootimg_init_new(struct bootimg *img)
{
    memset(img, 0, sizeof(struct bootimg));
    memcpy(img->hdr.magic, BOOT_MAGIC, BOOT_MAGIC_SIZE);
    img->hdr.page_size = DEFAULT_PAGE_SIZE;
}

int libbootimg_init_load(struct bootimg *img, const char *path)
{
    return libbootimg_init_load_parts(img, path, 1, 1, 1);
}

int libbootimg_init_load_parts(struct bootimg *img, const char *path,
                               int load_kernel, int load_rd, int load_second)
{
    int res = 0;
    long addr;

    libbootimg_init_new(img);

    res = libbootimg_load_header(&img->hdr, path);
    if(res < 0)
    {
        libbootimg_destroy(img);
        return res;
    }

    FILE *f = fopen(path, "r");
    if(!f)
        return -errno;

    addr = img->hdr.page_size;

    // Read kernel
    if(load_kernel)
    {
        img->kernel = malloc(img->hdr.kernel_size);

        if(fseek(f, addr, SEEK_SET) < 0)
            goto fail;

        if(fread(img->kernel, img->hdr.kernel_size, 1, f) != 1)
            goto fail;
    }

    addr += align_size(img->hdr.kernel_size, img->hdr.page_size);

    // Read ramdisk
    if(load_rd)
    {
        img->ramdisk = malloc(img->hdr.ramdisk_size);

        if(fseek(f, addr, SEEK_SET) < 0)
            goto fail;

        if(fread(img->ramdisk, img->hdr.ramdisk_size, 1, f) != 1)
            goto fail;
    }

    addr += align_size(img->hdr.ramdisk_size, img->hdr.page_size);

    // Read second
    if(load_second && img->hdr.second_size > 0)
    {
        img->second = malloc(img->hdr.second_size);

        if(fseek(f, addr, SEEK_SET) < 0)
            goto fail;

        if(fread(img->second, img->hdr.second_size, 1, f) != 1)
            goto fail;
    }

    fseek(f, 0, SEEK_END);
    img->size = ftell(f);

    fclose(f);
    return 0;
fail:
    res = -errno;
    libbootimg_destroy(img);
    fclose(f);
    return res;
}

void libbootimg_destroy(struct bootimg *b)
{
    free(b->kernel);
    free(b->ramdisk);
    free(b->second);

    b->kernel = b->ramdisk = b->second = NULL;
}

int libbootimg_load_header(struct boot_img_hdr *hdr, const char *path)
{
    FILE *f = fopen(path, "r");
    if(!f)
        return -errno;

    int res = fread(hdr, sizeof(struct boot_img_hdr), 1, f);
    if(res == 1)
    {
        if(memcmp(hdr->magic, BOOT_MAGIC, BOOT_MAGIC_SIZE) == 0)
            res = 0;
        else
            res = -EIO;
    }
    else
        res = errno ? -errno : -EIO;

    fclose(f);
    return res;
}

static int dump_part(uint8_t *data, unsigned len, const char *dest)
{
    int res = 0;
    FILE *f = fopen(dest, "w");
    if(!f)
        return -errno;

    if(fwrite(data, len, 1, f) != 1)
        res = -errno;

    fclose(f);
    return res;
}

int libbootimg_dump_kernel(struct bootimg *b, const char *dest)
{
    return dump_part(b->kernel, b->hdr.kernel_size, dest);
}

int libbootimg_dump_ramdisk(struct bootimg *b, const char *dest)
{
    return dump_part(b->ramdisk, b->hdr.ramdisk_size, dest);
}

int libbootimg_dump_second(struct bootimg *b, const char *dest)
{
    if(b->hdr.second_size == 0)
        return -ENOENT;
    return dump_part(b->second, b->hdr.second_size, dest);
}

int libbootimg_dump(struct bootimg *b, const char *dest_dir)
{
    char dest[MAX_PATH_LEN];
    int res = 0;

    snprintf(dest, sizeof(dest), "%s/zImage", dest_dir);
    res = libbootimg_dump_kernel(b, dest);

    if(res == 0)
    {
        snprintf(dest, sizeof(dest), "%s/initrd.img", dest_dir);
        res = libbootimg_dump_ramdisk(b, dest);
    }

    if(res == 0 && b->hdr.second_size)
    {
        snprintf(dest, sizeof(dest), "%s/second.img", dest_dir);
        res = libbootimg_dump_second(b, dest);
    }
    return res;
}

static int load_part(uint8_t **data, const char *src)
{
    struct stat info;
    if(stat(src, &info) < 0)
        return -errno;

    if(info.st_size > INT_MAX)
        return -EFBIG;

    FILE *f = fopen(src, "r");
    if(!f)
        return -errno;

    int res = info.st_size;
    *data = realloc(*data, info.st_size);

    if(fread(*data, info.st_size, 1, f) != 1)
    {
        res = -errno;
        free(*data);
        *data = NULL;
    }

    fclose(f);
    return res;
}

int libbootimg_load_kernel(struct bootimg *b, const char *src)
{
    int res = load_part(&b->kernel, src);
    if(res >= 0)
        b->hdr.kernel_size = res;
    return res;
}

int libbootimg_load_ramdisk(struct bootimg *b, const char *src)
{
    int res = load_part(&b->ramdisk, src);
    if(res >= 0)
        b->hdr.ramdisk_size = res;
    return res;
}

int libbootimg_load_second(struct bootimg *b, const char *src)
{
    int res = load_part(&b->second, src);
    if(res >= 0)
        b->hdr.second_size = res;
    return res;
}

// 32bit FNV-1a hash algorithm
// http://isthe.com/chongo/tech/comp/fnv/#FNV-1a
static uint32_t calc_fnv_hash(void *data, unsigned len)
{
    static const uint32_t FNV_prime = 16777619U;
    static const uint32_t offset_basis = 2166136261U;

    uint32_t *d = (uint32_t*)data;
    uint32_t i, max;
    uint32_t hash = offset_basis;

    max = len/4;

    // 32 bit data
    for(i = 0; i < max; ++i)
    {
        hash ^= d[i];
        hash *= FNV_prime;
    }

    // last bits
    for(i *= 4; i < len; ++i)
    {
        hash ^= (uint32_t) ((uint8_t*)data)[i];
        hash *= FNV_prime;
    }
    return hash;
}

static void fill_id_hashes(struct bootimg *b)
{
    b->hdr.id[0] = calc_fnv_hash(b->kernel, b->hdr.kernel_size);
    b->hdr.id[1] = calc_fnv_hash(b->ramdisk, b->hdr.ramdisk_size);
    b->hdr.id[2] = calc_fnv_hash(b->second, b->hdr.second_size);

    b->hdr.id[3] = calc_fnv_hash(&b->hdr.kernel_addr, sizeof(b->hdr.kernel_addr));
    b->hdr.id[4] = calc_fnv_hash(&b->hdr.ramdisk_addr, sizeof(b->hdr.ramdisk_addr));
    b->hdr.id[5] = calc_fnv_hash(&b->hdr.second_addr, sizeof(b->hdr.second_addr));
    b->hdr.id[6] = calc_fnv_hash(&b->hdr.tags_addr, sizeof(b->hdr.tags_addr));
    b->hdr.id[7] = calc_fnv_hash(b->hdr.cmdline, strlen((char*)b->hdr.cmdline));
}

int libbootimg_write_img(struct bootimg *b, const char *dest)
{
    if(b->hdr.kernel_size == 0 || b->hdr.ramdisk_size == 0 || b->hdr.page_size < sizeof(b->hdr))
        return -EINVAL;

    int res = 0;
    FILE *f = fopen(dest, "w");
    if(!f)
        return -errno;

    // make sure it ends with 0
    b->hdr.cmdline[BOOT_ARGS_SIZE-1] = 0;

    fill_id_hashes(b);

    size_t to_write;
    char *blank = malloc(b->hdr.page_size);
    memset(blank, 0, b->hdr.page_size);

    // write header
    if(fwrite(&b->hdr, sizeof(b->hdr), 1, f) != 1)
        goto fail;

    to_write = align_size(sizeof(b->hdr), b->hdr.page_size) - sizeof(b->hdr);
    if(fwrite(blank, sizeof(char), to_write, f) != to_write)
        goto fail;

    // write kernel
    if(fwrite(b->kernel, b->hdr.kernel_size, 1, f) != 1)
        goto fail;

    to_write = align_size(b->hdr.kernel_size, b->hdr.page_size) - b->hdr.kernel_size;
    if(fwrite(blank, sizeof(char), to_write, f) != to_write)
        goto fail;

    // write ramdisk
    if(fwrite(b->ramdisk, b->hdr.ramdisk_size, 1, f) != 1)
        goto fail;

    to_write = align_size(b->hdr.ramdisk_size, b->hdr.page_size) - b->hdr.ramdisk_size;
    if(fwrite(blank, sizeof(char), to_write, f) != to_write)
        goto fail;

    // write second
    if(b->hdr.second_size != 0)
    {
        if(fwrite(b->second, b->hdr.second_size, 1, f) != 1)
            goto fail;

        to_write = align_size(b->hdr.second_size, b->hdr.page_size) - b->hdr.second_size;
        if(fwrite(blank, sizeof(char), to_write, f) != to_write)
            goto fail;
    }

    // bootimg size (abootimg compatibility)
    if(b->size != 0)
    {
        if((int)b->size < ftell(f))
        {
            res = -EFBIG;
            remove(dest);
            goto exit;
        }

        if(b->size_is_max_only == 0)
            ftruncate(fileno(f), b->size);
    }

    goto exit;
fail:
    res = -errno;
    remove(dest);
exit:
    fclose(f);
    free(blank);
    return res;
}

int libbootimg_write_img_and_destroy(struct bootimg *b, const char *dest)
{
    int res = libbootimg_write_img(b, dest);
    libbootimg_destroy(b);
    return res;
}

int libbootimg_load_config(struct bootimg *b, const char *src, int *error_line)
{
    FILE *f = fopen(src, "r");
    if(!f)
        return -errno;

    int res = 0;
    int line_num = 0;
    char line[1024];
    while(fgets(line, sizeof(line), f))
    {
        if(libbootimg_load_config_line(b, line) < 0)
        {
            res = -1;
            if(error_line)
                *error_line = line_num;
            goto exit;
        }
        ++line_num;
    }

exit:
    fclose(f);
    return res;
}

int libbootimg_load_config_line(struct bootimg *b, char *line)
{
    char *s, *e;
    char *name_e;
    char *arg_s;
    size_t n_to_cmp;

    for(s = line; isspace(*s); ++s);

    for(e = s+strlen(s)-1; isspace(*e); --e)
        *e = 0;

    if(*s == 0 || (name_e = strchr(s, '=')) == NULL)
        return 0;

    arg_s = name_e+1;

    for(; isspace(*(name_e-1)) && name_e > s; --name_e);
    for(; isspace(*arg_s); ++arg_s);

    n_to_cmp = name_e-s;

    if(strncmp("bootsize", s, n_to_cmp) == 0)
        b->size = strtoll(arg_s, NULL, 16);
    else if(strncmp("pagesize", s, n_to_cmp) == 0)
        b->hdr.page_size = strtoll(arg_s, NULL, 16);
    else if(strncmp("kerneladdr", s, n_to_cmp) == 0)
        b->hdr.kernel_addr = strtoll(arg_s, NULL, 16);
    else if(strncmp("ramdiskaddr", s, n_to_cmp) == 0)
        b->hdr.ramdisk_addr = strtoll(arg_s, NULL, 16);
    else if(strncmp("secondaddr", s, n_to_cmp) == 0)
        b->hdr.second_addr = strtoll(arg_s, NULL, 16);
    else if(strncmp("tagsaddr", s, n_to_cmp) == 0)
        b->hdr.tags_addr = strtoll(arg_s, NULL, 16);
    else if(strncmp("name", s, n_to_cmp) == 0)
        strncpy((char*)b->hdr.name, arg_s, BOOT_NAME_SIZE);
    else if(strncmp("cmdline", s, n_to_cmp) == 0)
        strncpy((char*)b->hdr.cmdline, arg_s, BOOT_ARGS_SIZE);
    else
        return -1;
    return 0;
}

int libbootimg_write_config(struct bootimg *b, const char *dst)
{
    FILE *f = fopen(dst, "w");
    if(!f)
        return -errno;

    int res = fprintf(f,
        "bootsize = 0x%X\n"
        "pagesize = 0x%X\n"
        "kerneladdr = 0x%X\n"
        "ramdiskaddr = 0x%X\n"
        "secondaddr = 0x%X\n"
        "tagsaddr = 0x%X\n"
        "name = %s\n"
        "cmdline = %s\n",
        b->size, b->hdr.page_size, b->hdr.kernel_addr, b->hdr.ramdisk_addr,
        b->hdr.second_addr, b->hdr.tags_addr, b->hdr.name, b->hdr.cmdline);

    fclose(f);
    return res;
}

uint32_t libbootimg_version(void)
{
    return LIBBOOTIMG_VERSION;
}

const char *libbootimg_version_str(void)
{
    return LIBBOOTIMG_VERSION_STR;
}
