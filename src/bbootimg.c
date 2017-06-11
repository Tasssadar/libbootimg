#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../include/libbootimg.h"

#define ACT_HELP    0
#define ACT_EXTRACT 1
#define ACT_UPDATE  2
#define ACT_CREATE  3

static const char *default_fname_cfg = "bootimg.cfg";
static const char *default_fname_blobs[] = {
    "zImage",     // LIBBOOTIMG_BLOB_KERNEL
    "initrd.img", // LIBBOOTIMG_BLOB_RAMDISK
    "stage2.img", // LIBBOOTIMG_BLOB_SECOND
    "dtb.img",    // LIBBOOTIMG_BLOB_DTB
};

static const char *blob_names[] = {
    "kernel",       // LIBBOOTIMG_BLOB_KERNEL
    "ramdisk",      // LIBBOOTIMG_BLOB_RAMDISK
    "second stage", // LIBBOOTIMG_BLOB_SECOND
    "DTB",          // LIBBOOTIMG_BLOB_DTB
};

struct bbootimg_info
{
    struct bootimg img;
    off_t img_size;
    int size_is_max_only;
    int act;
    const char *fname_img;
    const char *fname_cfg;
    const char *fname_blobs[LIBBOOTIMG_BLOB_CNT];
};

static void print_help(const char *prog_name)
{
    printf(
    "bbootimg %s\n"
    "Manipulate Android Boot Images.\n"
    "This is abootimg-compatible implementation using libbootimg.\n"
    "\n"
    "%s [-h,--help]     - print usage\n"
    "\n"
    "%s -i <bootimg>    - print image information\n"
    "\n"
    "%s -j <bootimg>    - print image information in JSON\n"
    "\n"
    "%s -x <bootimg> [<bootimg.cfg> [<kernel> [<ramdisk> [<secondstage> [<dtb>]]]]]\n"
    "    extract objects from boot image:\n"
    "    - config file (bootimg.cfg)\n"
    "    - kernel image (zImage)\n"
    "    - ramdisk image (initrd.img)\n"
    "    - second stage image (stage2.img)\n"
    "\n"
    "%s -u <bootimg> [-c \"param=value\"] [-f <bootimg.cfg>] [-k <kernel>] [-r <ramdisk>] [-s <secondstage>] [-d <dtb> ] [-m]\n"
    "    update current boot image with objects given in command line\n"
    "    - header informations given in arguments (several can be provided)\n"
    "    - header informations given in config file\n"
    "    - kernel image\n"
    "    - ramdisk image\n"
    "    - second stage image\n"
    "    - device tree blob\n"
    "    - -m means that bootsize is used as \"maximum\", i.e. the image will not be padded with 0 to this size\n"
    "\n"
    "%s --create <bootimg> [-c \"param=value\"] [-f <bootimg.cfg>] -k <kernel> -r <ramdisk> [-s <secondstage>] [-d <dtb> ] [-m]\n"
    "    create a new image from scratch.\n"
    "    arguments are the same as for -u.\n"
    "    kernel and ramdisk are mandatory.\n"
    "\n"
    "Config params:\n"
    "    bootsize = 0x1234                   - target size in B, image will always be this big  unless -m is used (0 means ignore)\n"
    "    pagesize = 0x1234                   - Page size in bytes\n"
    "    kerneladdr = 0x1234                 - kernel load address\n"
    "    ramdiskaddr = 0x1234                - ramdisk load address\n"
    "    secondaddr = 0x1234                 - 2nd stage load address\n"
    "    tagsaddr = 0x1234                   - atags address\n"
    "    name = string without quotes        - name of the image, max 16 characters\n"
    "    cmdline = string without quotes     - cmdline, max 512 characters\n"
    ,libbootimg_version_str(), prog_name, prog_name, prog_name, prog_name, prog_name, prog_name);
}


static int write_config(struct bbootimg_info *i, const char *dst)
{
    int res;
    FILE *f;

    f = fopen(dst, "w");
    if(!f)
        return -errno;

    res = fprintf(f,
        "bootsize = 0x%X\n"
        "pagesize = 0x%X\n"
        "kerneladdr = 0x%X\n"
        "ramdiskaddr = 0x%X\n"
        "secondaddr = 0x%X\n"
        "tagsaddr = 0x%X\n"
        "name = %s\n"
        "cmdline = %s\n",
        (uint32_t)i->img_size, i->img.hdr.page_size, i->img.hdr.kernel_addr, i->img.hdr.ramdisk_addr,
        i->img.hdr.second_addr, i->img.hdr.tags_addr, i->img.hdr.name, i->img.hdr.cmdline);

    fclose(f);
    return res;
}

static void parse_config_str(char *dest, const char *arg_start, const char *arg_end, size_t maxlen)
{
    size_t len = 0;

    if(*arg_start)
    {
        maxlen -= 1; // it includes the NULL

        len = arg_end - arg_start;
        if(len > maxlen)
            len = maxlen;

        strncpy(dest, arg_start, len);
    }

    dest[len] = 0;
}

static int load_config_line(struct bbootimg_info *i, const char *line)
{
    const char *start, *end;
    char *name_e;
    char *arg_s;
    size_t n_to_cmp, len;

    for(start = line; isspace(*start); ++start);

    for(end = start+strlen(start); isspace(*(end-1)); --end);

    if(*start == 0 || (name_e = strchr(start, '=')) == NULL)
        return 0;

    arg_s = name_e+1;

    for(; isspace(*(name_e-1)) && name_e > start; --name_e);
    for(; isspace(*arg_s); ++arg_s);

    n_to_cmp = name_e - start;

    if(strncmp("bootsize", start, n_to_cmp) == 0)
        i->img_size = strtoll(arg_s, NULL, 0);
    else if(strncmp("pagesize", start, n_to_cmp) == 0)
        i->img.hdr.page_size = strtoll(arg_s, NULL, 0);
    else if(strncmp("kerneladdr", start, n_to_cmp) == 0)
        i->img.hdr.kernel_addr = strtoll(arg_s, NULL, 0);
    else if(strncmp("ramdiskaddr", start, n_to_cmp) == 0)
        i->img.hdr.ramdisk_addr = strtoll(arg_s, NULL, 0);
    else if(strncmp("secondaddr", start, n_to_cmp) == 0)
        i->img.hdr.second_addr = strtoll(arg_s, NULL, 0);
    else if(strncmp("tagsaddr", start, n_to_cmp) == 0)
        i->img.hdr.tags_addr = strtoll(arg_s, NULL, 0);
    else if(strncmp("name", start, n_to_cmp) == 0)
        parse_config_str((char*)i->img.hdr.name, arg_s, end, BOOT_NAME_SIZE);
    else if(strncmp("cmdline", start, n_to_cmp) == 0)
        parse_config_str((char*)i->img.hdr.cmdline, arg_s, end, BOOT_ARGS_SIZE);
    else
        return -1;
    return 0;
}

static int load_config(struct bbootimg_info *i, const char *src, int *error_line)
{
    FILE *f;
    int res = 0;
    int line_num = 0;
    char line[1024];

    f = fopen(src, "r");
    if(!f)
        return -errno;

    while(fgets(line, sizeof(line), f))
    {
        if(load_config_line(i, line) < 0)
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

static int load_bootimg(struct bootimg *b, const char *path)
{
    int res = libbootimg_init_load(b, path, LIBBOOTIMG_LOAD_ALL);
    if(res < 0)
    {
        fprintf(stderr, "Failed to load boot image (%s)!", libbootimg_error_str(res));
        return -res;
    }
    return 0;
}

static off_t get_bootimg_size(const char *path)
{
    struct stat info;
    if(stat(path, &info) < 0)
    {
        fprintf(stderr, "Failed to get boot image size (%s)!", strerror(errno));
        return -1;
    }

    // If this is a block device, stat will report zero size.
    // abootimg uses libblkid to get the correct size, but
    // I don't wanna drag in any dependencies.
    if(info.st_size == 0)
    {
        off_t size;
        FILE *f;

        f = fopen(path, "r");
        if(!f)
        {
            fprintf(stderr, "Failed to get boot image size (%s)!", strerror(errno));
            return -1;
        }

        fseek(f, 0, SEEK_END);
        size = ftell(f);
        fclose(f);

        if(size <= 0)
        {
            fprintf(stderr, "Failed to get boot image size (fseek -> ftell failed, %s)!", strerror(errno));
            return -1;
        }
        return size;
    }
    else
    {
        return info.st_size;
    }
}

static void load_default_filenames(struct bbootimg_info *i)
{
    int x;

    i->fname_cfg = default_fname_cfg;

    for(x = 0; x < LIBBOOTIMG_BLOB_CNT; ++x)
        i->fname_blobs[x] = default_fname_blobs[x];
}

static int print_info(const char *path)
{
    int i;
    int res;
    off_t size;
    struct bootimg img;
    char name[BOOT_NAME_SIZE+1];

    res = libbootimg_init_load(&img, path, LIBBOOTIMG_LOAD_HDR_ONLY);
    if(res < 0)
    {
        fprintf(stderr, "Failed to load bootimg \"%s\" (%s)!\n", path, libbootimg_error_str(res));
        return 1;
    }

    if((size = get_bootimg_size(path)) < 0)
        return 1;

    snprintf(name, sizeof(name), "%s", img.hdr.name);

    img.hdr.cmdline[BOOT_ARGS_SIZE-1] = 0;

    printf ("\nAndroid Boot Image Info:\n\n");
    printf ("* architecture = %s\n\n",
            libbootimg_architecture() == ARCH_64_BITS ? "64bits" : "32bits");

    printf ("* file name = %s\n\n", path);

    printf ("* image size = %ld bytes (%.2f MB)\n", size, (double)size/0x100000);
    printf ("  page size  = %u bytes\n\n", img.hdr.page_size);

    printf ("* Boot Name = \"%s\" [ ", name);
    for (i = 0; i < BOOT_NAME_SIZE && name[i] != '\0'; ++i)
    {
        printf ("0x%02X ", name[i]);
    }
    printf ("]\n\n", name);

    printf ("* kernel size       = %u bytes (%.2f MB)\n", img.hdr.kernel_size, (double)img.hdr.kernel_size/0x100000);
    printf ("  ramdisk size      = %u bytes (%.2f MB)\n", img.hdr.ramdisk_size, (double)img.hdr.ramdisk_size/0x100000);
    if (img.hdr.second_size)
        printf ("  second stage size = %u bytes (%.2f MB)\n", img.hdr.second_size, (double)img.hdr.second_size/0x100000);
    if (img.hdr.dt_size)
        printf ("  device tree size  = %u bytes (%.2f MB)\n", img.hdr.dt_size, (double)img.hdr.dt_size/0x100000);

    printf ("\n* load addresses:\n");
    printf ("  kernel:       0x%08x\n", img.hdr.kernel_addr);
    printf ("  ramdisk:      0x%08x\n", img.hdr.ramdisk_addr);
    if (img.hdr.second_size)
        printf ("  second stage: 0x%08x\n", img.hdr.second_addr);
    printf ("  tags:         0x%08x\n\n", img.hdr.tags_addr);

    if (img.hdr.cmdline[0])
        printf ("* cmdline = %s\n\n", img.hdr.cmdline);
    else
        printf ("* empty cmdline\n");

    printf ("* id = ");
    for (i = 0; i < 8; ++i)
        printf ("0x%08x ", img.hdr.id[i]);
    printf ("\n\n");

    libbootimg_destroy(&img);
    return 0;
}

static int print_json(const char *path)
{
    int i;
    int res;
    off_t size;
    struct bootimg img;
    char name[BOOT_NAME_SIZE+1];

    res = libbootimg_init_load(&img, path, LIBBOOTIMG_LOAD_HDR_ONLY);
    if(res < 0)
    {
        fprintf(stderr, "Failed to load bootimg \"%s\" (%s)!\n", path, libbootimg_error_str(res));
        return 1;
    }

    if((size = get_bootimg_size(path)) < 0)
        return 1;

    snprintf(name, sizeof(name), "%s", img.hdr.name);

    img.hdr.cmdline[BOOT_ARGS_SIZE-1] = 0;

    printf("{\n");
    printf("    \"bbootimg_version\": %u,\n", libbootimg_version());
    printf("    \"img_size\": %ld,\n", size);
    printf("    \"boot_img_hdr\": {\n");
    printf("        \"kernel_size\": %u,\n", img.hdr.kernel_size);
    printf("        \"kernel_addr\": %u,\n", img.hdr.kernel_addr);
    printf("        \"ramdisk_size\": %u,\n", img.hdr.ramdisk_size);
    printf("        \"ramdisk_addr\": %u,\n", img.hdr.ramdisk_addr);
    printf("        \"second_size\": %u,\n", img.hdr.second_size);
    printf("        \"second_addr\": %u,\n", img.hdr.second_addr);
    printf("        \"tags_addr\": %u,\n", img.hdr.tags_addr);
    printf("        \"page_size\": %u,\n", img.hdr.page_size);
    printf("        \"name\": \"%s\",\n", name);
    printf("        \"cmdline\": \"%s\",\n", img.hdr.cmdline);
    printf("        \"dt_size\": %u,\n", img.hdr.dt_size);
    printf("        \"id\": [\n");
    for(i = 0; i < 8; ++i)
        printf("            %u%c\n", img.hdr.id[i], (i != 7) ? ',' : ' ');
    printf("        ]\n"
           "    }\n"
           "}\n");

    libbootimg_destroy(&img);
    return 0;
}

static int extract_bootimg(struct bbootimg_info *i)
{
    int x;
    int res;
    struct bootimg_blob *blob;

    res = libbootimg_init_load(&i->img, i->fname_img, LIBBOOTIMG_LOAD_ALL);
    if(res < 0)
    {
        fprintf(stderr, "Failed to load boot image (%s)!\n", libbootimg_error_str(res));
        return -res;
    }

    if((i->img_size = get_bootimg_size(i->fname_img)) < 0)
        return -1;

    printf("writing boot image config in %s\n", i->fname_cfg);
    res = write_config(i, i->fname_cfg);
    if(res < 0)
    {
        fprintf(stderr, "Failed to write bootimg cfg (%s)!\n", strerror(-res));
        return -res;
    }

    for(x = 0; x < LIBBOOTIMG_BLOB_CNT; ++x)
    {
        blob = &i->img.blobs[x];

        if(*blob->size == 0)
            continue;

        printf("extracting %s in %s\n", blob_names[x], i->fname_blobs[x]);
        res = libbootimg_dump_blob(blob, i->fname_blobs[x]);
        if(res < 0)
        {
            fprintf(stderr, "Failed to extract %s (%s)!\n", blob_names[x], libbootimg_error_str(res));
            return res;
        }
    }

    libbootimg_destroy(&i->img);
    return 0;
}

static int copy_file(FILE *in, const char *dst)
{
#define CPY_BUFF_SIZE (512*1024)
    FILE *out;
    int res = -1;
    size_t read;
    char *buff = NULL;

    out = fopen(dst, "w");
    if(!out)
    {
        fprintf(stderr, "Failed to open dst file (%s)!\n", strerror(errno));
        return -1;
    }

    buff = malloc(CPY_BUFF_SIZE);

    while((read = fread(buff, 1, CPY_BUFF_SIZE, in)) > 0)
    {
        if(fwrite(buff, 1, read, out) != read)
        {
            fprintf(stderr, "Failed to write data to dst file (%s)!\n", strerror(errno));
            goto exit;
        }
    }

    res = 0;
exit:
    free(buff);
    fclose(out);
    return res;
}

static int update_bootimg(struct bbootimg_info *i)
{
    int x;
    int res = -1;
    FILE *tmp = NULL;
    struct bootimg_blob *blob;

    for(x = 0; x < LIBBOOTIMG_BLOB_CNT; ++x)
    {
        if(!i->fname_blobs[x])
            continue;

        blob = &i->img.blobs[x];

        printf("reading %s from %s\n", blob_names[x], i->fname_blobs[x]);
        res = libbootimg_load_blob(blob, i->fname_blobs[x]);
        if(res < 0)
        {
            fprintf(stderr, "Failed to load %s (%s)!\n", blob_names[x], libbootimg_error_str(res));
            goto exit;
        }
    }

    printf("Writing Boot Image %s\n", i->fname_img);

    tmp = tmpfile();
    if(!tmp)
    {
        fprintf(stderr, "Failed to create tmp file (%s)!\n", strerror(errno));
        goto exit;
    }

    res = libbootimg_write_img_fileptr(&i->img, tmp);
    if(res < 0)
    {
        fprintf(stderr, "Failed to create boot image (%s)!\n", libbootimg_error_str(res));
        goto exit;
    }

    // bootimg size (abootimg compatibility)
    if(i->img_size != 0)
    {
        if(i->img_size < ftell(tmp))
        {
            fprintf(stderr, "Failed to create boot image: the result image is too big\n");
            res = -1;
            goto exit;
        }

        if(i->size_is_max_only == 0)
            ftruncate(fileno(tmp), i->img_size);
    }

    rewind(tmp);
    res = copy_file(tmp, i->fname_img);

exit:
    if(tmp)
        fclose(tmp);
    libbootimg_destroy(&i->img);
    return res;
}

static int execute_action(struct bbootimg_info *i)
{
    switch(i->act)
    {
        case ACT_EXTRACT:
            return extract_bootimg(i);
        case ACT_UPDATE:
            return update_bootimg(i);
        case ACT_CREATE:
        {
            if(!i->fname_blobs[LIBBOOTIMG_BLOB_KERNEL] || !i->fname_blobs[LIBBOOTIMG_BLOB_RAMDISK])
            {
                fprintf(stderr, "You have to specify both ramdisk and kernel to create boot image!\n");
                return EINVAL;
            }
            return update_bootimg(i);
        }
    }
    return EINVAL;
}

int main(int argc, const char *argv[])
{
    int i;

    struct bbootimg_info info;
    memset(&info, 0, sizeof(info));

    libbootimg_init_new(&info.img);

    for(i = 1; i < argc; ++i)
    {
        if(strcmp("-h", argv[i]) == 0 || strcmp("--help", argv[i]) == 0)
        {
            print_help(argv[0]);
            return 0;
        }

        if(strcmp("-m", argv[i]) == 0)
            info.size_is_max_only = 1;

        if(i+1 >= argc)
            continue;

        if(strcmp("-i", argv[i]) == 0)
            return print_info(argv[i+1]);
        else if(strcmp("-j", argv[i]) == 0)
            return print_json(argv[i+1]);

        // actions
        if(strcmp("-x", argv[i]) == 0)
        {
            int blob_itr;

            load_default_filenames(&info);

            info.act = ACT_EXTRACT;
            info.fname_img = argv[++i];

            if(++i < argc)
                info.fname_cfg = argv[i];

            for(blob_itr = 0; ++i < argc && blob_itr < LIBBOOTIMG_BLOB_CNT; ++blob_itr)
                info.fname_blobs[blob_itr] = argv[i];

            break;
        }
        else if(strcmp("-u", argv[i]) == 0)
        {
            info.act = ACT_UPDATE;
            info.fname_img = argv[++i];

            if (load_bootimg(&info.img, info.fname_img) != 0)
               return -1;

            if((info.img_size = get_bootimg_size(info.fname_img)) < 0)
                return -1;
        }
        else if(strcmp("--create", argv[i]) == 0)
        {
            info.act = ACT_CREATE;
            info.fname_img = argv[++i];
        }
        // params
        else if(strcmp("-c", argv[i]) == 0)
        {
            if(load_config_line(&info, argv[++i]) < 0)
            {
                fprintf(stderr, "Invalid config option \"%s\"\n\n", argv[i]);
                goto exit_help;
            }
        }
        else if(strcmp("-f", argv[i]) == 0)
        {
            info.fname_cfg = argv[++i];
            printf("reading config file %s\n", info.fname_cfg);

            int line = -1;
            int res = load_config(&info, info.fname_cfg, &line);
            if(res < 0)
            {
                res = -res;
                fprintf(stderr, "Failed to load config (%s), error on line %d!\n", strerror(res), line);
                goto exit;
            }
        }
        else if(strcmp("-k", argv[i]) == 0)
            info.fname_blobs[LIBBOOTIMG_BLOB_KERNEL] = argv[++i];
        else if(strcmp("-r", argv[i]) == 0)
            info.fname_blobs[LIBBOOTIMG_BLOB_RAMDISK] = argv[++i];
        else if(strcmp("-s", argv[i]) == 0)
            info.fname_blobs[LIBBOOTIMG_BLOB_SECOND] = argv[++i];
        else if(strcmp("-d", argv[i]) == 0)
            info.fname_blobs[LIBBOOTIMG_BLOB_DTB] = argv[++i];
        else
        {
            fprintf(stderr, "Unknown argument: %s\n\n", argv[i]);
            goto exit_help;
        }
    }

    if(info.act != ACT_HELP)
        return execute_action(&info) >= 0 ? 0 : 1;

exit_help:
    print_help(argv[0]);
exit:
    libbootimg_destroy(&info.img);
    return EINVAL;
}
