#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>

#include "../include/libbootimg.h"

#define DEFAULT_PAGE_SIZE 2048

static inline unsigned align_size(unsigned size, unsigned page_size)
{
    return ((size + page_size - 1)/page_size)*page_size;
}

static int translate_errnum(int errnum)
{
    switch(errno)
    {
        case EIO:     return LIBBOOTIMG_ERROR_IO;
        case EACCES:  return LIBBOOTIMG_ERROR_ACCESS;
        case ENOENT:  return LIBBOOTIMG_ERROR_NOT_FOUND;

        default:      return LIBBOOTIMG_ERROR_OTHER;
    }
}

static int translate_fread_error(FILE *f)
{
    if(ferror(f))
        return LIBBOOTIMG_ERROR_IO;
    else if(feof(f))
        return LIBBOOTIMG_ERROR_IMG_EOF;
    else
        return LIBBOOTIMG_ERROR_OTHER;
}

// 32bit FNV-1a hash algorithm
// http://isthe.com/chongo/tech/comp/fnv/#FNV-1a
static uint32_t calc_fnv_hash(void *data, unsigned len)
{
    const uint32_t FNV_prime = 16777619U;
    const uint32_t offset_basis = 2166136261U;

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
    int i = 0;

    // hash blobs
    for(; i < LIBBOOTIMG_BLOB_CNT && i < 5; ++i)
        b->hdr.id[i] = calc_fnv_hash(b->blobs[i].data, *b->blobs[i].size);

    // hash kernel, ramdisk and second _addr and _size together
    b->hdr.id[i++] = calc_fnv_hash(&b->hdr.kernel_size, sizeof(uint32_t)*6);

    // hash tags_addr, page_size, dt_size and unused together
    b->hdr.id[i++] = calc_fnv_hash(&b->hdr.tags_addr, sizeof(uint32_t)*4);

    // cmdline is directly after name, so hash them together
    b->hdr.id[i++] = calc_fnv_hash(b->hdr.name, BOOT_NAME_SIZE + strlen((char*)b->hdr.cmdline));
}



void libbootimg_init_new(struct bootimg *img)
{
    memset(img, 0, sizeof(struct bootimg));
    memcpy(img->hdr.magic, BOOT_MAGIC, BOOT_MAGIC_SIZE);
    img->hdr.page_size = DEFAULT_PAGE_SIZE;

    img->blobs[LIBBOOTIMG_BLOB_KERNEL].size = &img->hdr.kernel_size;
    img->blobs[LIBBOOTIMG_BLOB_RAMDISK].size = &img->hdr.ramdisk_size;
    img->blobs[LIBBOOTIMG_BLOB_SECOND].size = &img->hdr.second_size;
    img->blobs[LIBBOOTIMG_BLOB_DTB].size = &img->hdr.dt_size;
}

int libbootimg_init_load(struct bootimg *img, const char *path, int load_blob_mask)
{
    int i;
    FILE *f;
    int res = 0;
    int64_t addr;
    struct bootimg_blob *blob;

    libbootimg_init_new(img);

    res = libbootimg_load_header(&img->hdr, path);
    if(res < 0)
    {
        libbootimg_destroy(img);
        return res;
    }

    f = fopen(path, "r");
    if(!f)
        return translate_errnum(errno);

    addr = img->hdr.page_size;

    for(i = 0; i < LIBBOOTIMG_BLOB_CNT; ++i)
    {
        blob = &img->blobs[i];

        if((load_blob_mask & (1 << i)) && *blob->size != 0)
        {
            if(fseek(f, addr, SEEK_SET) < 0)
            {
                if(errno == EINVAL)
                    res = LIBBOOTIMG_ERROR_IMG_EOF;
                else
                    res = translate_errnum(errno);
                goto fail;
            }

            blob->data = malloc(*blob->size);

            if(fread(blob->data, *blob->size, 1, f) != 1)
            {
                res = translate_fread_error(f);
                goto fail;
            }
        }

        addr += align_size(*blob->size, img->hdr.page_size);
    }

    fclose(f);
    return 0;

fail:
    libbootimg_destroy(img);
    fclose(f);
    return res;
}

void libbootimg_destroy(struct bootimg *b)
{
    struct bootimg_blob *blob = b->blobs;
    struct bootimg_blob * const blobs_end = blob + LIBBOOTIMG_BLOB_CNT;
    for(; blob != blobs_end; ++blob)
    {
        free(blob->data);
        blob->data = NULL;
    }
}

int libbootimg_load_header(struct boot_img_hdr *hdr, const char *path)
{
    int res = 0;
    FILE *f = fopen(path, "r");
    if(!f)
        return translate_errnum(errno);

    if(fread(hdr, sizeof(struct boot_img_hdr), 1, f) == 1)
    {
        if(memcmp(hdr->magic, BOOT_MAGIC, BOOT_MAGIC_SIZE) != 0)
            res = LIBBOOTIMG_ERROR_INVALID_MAGIC;
    }
    else
    {
        res = translate_fread_error(f);
    }

    fclose(f);
    return res;
}

int libbootimg_dump_blob(struct bootimg_blob *blob, const char *dest)
{
    FILE *f;
    int res = 0;

    if(blob->data == NULL)
        return LIBBOOTIMG_ERROR_NO_BLOB_DATA;

    f = fopen(dest, "w");
    if(!f)
        return translate_errnum(errno);

    if(fwrite(blob->data, *blob->size, 1, f) != 1)
        res = LIBBOOTIMG_ERROR_IO;

    fclose(f);
    return res;
}

int libbootimg_dump_kernel(struct bootimg *b, const char *dest)
{
    return libbootimg_dump_blob(&b->blobs[LIBBOOTIMG_BLOB_KERNEL], dest);
}

int libbootimg_dump_ramdisk(struct bootimg *b, const char *dest)
{
    return libbootimg_dump_blob(&b->blobs[LIBBOOTIMG_BLOB_RAMDISK], dest);
}

int libbootimg_dump_second(struct bootimg *b, const char *dest)
{
    return libbootimg_dump_blob(&b->blobs[LIBBOOTIMG_BLOB_SECOND], dest);
}

int libbootimg_dump_dtb(struct bootimg *b, const char *dest)
{
    return libbootimg_dump_blob(&b->blobs[LIBBOOTIMG_BLOB_DTB], dest);
}

int libbootimg_load_blob(struct bootimg_blob *blob, const char *src)
{
    FILE *f;
    int res = 0;
    uint8_t *data;
    struct stat info;

    if(stat(src, &info) < 0)
        return translate_errnum(errno);

    if(info.st_size > INT_MAX)
        return LIBBOOTIMG_ERROR_FILE_TOO_BIG;

    // probably /dev/null
    if(info.st_size == 0)
    {
        free(blob->data);
        blob->data = NULL;
        *blob->size = 0;
        return 0;
    }

    f = fopen(src, "r");
    if(!f)
        return translate_errnum(errno);

    data = malloc(info.st_size);

    if(fread(data, info.st_size, 1, f) == 1)
    {
        free(blob->data);
        blob->data = data;
        *blob->size = info.st_size;
    }
    else
    {
        res = translate_fread_error(f);
        free(data);
    }

    fclose(f);
    return res;
}

int libbootimg_load_kernel(struct bootimg *b, const char *src)
{
    return libbootimg_load_blob(&b->blobs[LIBBOOTIMG_BLOB_KERNEL], src);
}

int libbootimg_load_ramdisk(struct bootimg *b, const char *src)
{
    return libbootimg_load_blob(&b->blobs[LIBBOOTIMG_BLOB_RAMDISK], src);
}

int libbootimg_load_second(struct bootimg *b, const char *src)
{
    return libbootimg_load_blob(&b->blobs[LIBBOOTIMG_BLOB_SECOND], src);
}

int libbootimg_load_dtb(struct bootimg *b, const char *src)
{
    return libbootimg_load_blob(&b->blobs[LIBBOOTIMG_BLOB_DTB], src);
}

int libbootimg_write_img(struct bootimg *b, const char *dest)
{
    FILE *f;
    int res;

    if(b->hdr.kernel_size == 0 || b->hdr.ramdisk_size == 0)
        return LIBBOOTIMG_ERROR_MISSING_BLOB;

    if(b->hdr.page_size < sizeof(b->hdr))
        return LIBBOOTIMG_ERROR_INVALID_PAGESIZE;

    f = fopen(dest, "w");
    if(!f)
        return translate_errnum(errno);

    res = libbootimg_write_img_fileptr(b, f);

    fclose(f);
    return res;
}

int libbootimg_write_img_fileptr(struct bootimg *b, FILE *f)
{
    int i;
    int res = 0;
    char *blank = NULL;
    size_t padding;
    struct bootimg_blob *blob;
    int pos_start, pos_end;

    pos_start = ftell(f);
    if(pos_start < 0)
        return translate_errnum(errno);

    if(b->hdr.kernel_size == 0 || b->hdr.ramdisk_size == 0)
        return LIBBOOTIMG_ERROR_MISSING_BLOB;

    if(b->hdr.page_size < sizeof(b->hdr))
        return LIBBOOTIMG_ERROR_INVALID_PAGESIZE;

    // make sure it ends with 0
    b->hdr.cmdline[BOOT_ARGS_SIZE-1] = 0;

    // set unused field to 0 - we might not be handling something
    // which gets turned-on by this field, like with dtb
    b->hdr.unused = 0;

    fill_id_hashes(b);

    blank = malloc(b->hdr.page_size);
    memset(blank, 0, b->hdr.page_size);

    // write header
    if(fwrite(&b->hdr, sizeof(b->hdr), 1, f) != 1)
        goto fail_fwrite;

    padding = align_size(sizeof(b->hdr), b->hdr.page_size) - sizeof(b->hdr);
    if(fwrite(blank, 1, padding, f) != padding)
        goto fail_fwrite;

    for(i = 0; i < LIBBOOTIMG_BLOB_CNT; ++i)
    {
        blob = &b->blobs[i];

        if(*blob->size == 0)
            continue;

        if(fwrite(blob->data, *blob->size, 1, f) != 1)
            goto fail_fwrite;

        padding = align_size(*blob->size, b->hdr.page_size) - *blob->size;
        if(fwrite(blank, 1, padding, f) != padding)
            goto fail_fwrite;
    }

    pos_end = ftell(f);

    if(pos_end > 0)
        res = pos_end - pos_start;
    else
        res = translate_errnum(errno);

    goto exit;
fail_fwrite:
    res = LIBBOOTIMG_ERROR_IO;
exit:
    free(blank);
    return res;
}

int libbootimg_write_img_and_destroy(struct bootimg *b, const char *dest)
{
    int res = libbootimg_write_img(b, dest);
    libbootimg_destroy(b);
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

const char *libbootimg_error_str(int error)
{
    switch(error)
    {
        case LIBBOOTIMG_SUCCESS:                return "No errors";
        case LIBBOOTIMG_ERROR_IO:               return "Input/output error";
        case LIBBOOTIMG_ERROR_ACCESS:           return "Permission denied";
        case LIBBOOTIMG_ERROR_NOT_FOUND:        return "No such file or directory";
        case LIBBOOTIMG_ERROR_INVALID_MAGIC:    return "Corrupted boot image, invalid magic";
        case LIBBOOTIMG_ERROR_IMG_EOF:          return "Corrupted boot image, premature end of file";
        case LIBBOOTIMG_ERROR_NO_BLOB_DATA:     return "No data loaded into this blob";
        case LIBBOOTIMG_ERROR_FILE_TOO_BIG:     return "File is too big";
        case LIBBOOTIMG_ERROR_MISSING_BLOB:     return "Missing required blob (kernel or ramdisk)";
        case LIBBOOTIMG_ERROR_INVALID_PAGESIZE: return "Invalid pagesize value";

        case LIBBOOTIMG_ERROR_OTHER:            return "Unhandled error";
        default:                                return "Unknown error";
    }
}
