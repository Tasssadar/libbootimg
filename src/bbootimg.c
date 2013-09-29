#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "../include/libbootimg.h"

#define ACT_HELP    0
#define ACT_EXTRACT 1
#define ACT_UPDATE  2
#define ACT_CREATE  3

struct bbootimg_info
{
    struct bootimg img;
    int act;
    char *fname_img;
    char *fname_kernel;
    char *fname_ramdisk;
    char *fname_second;
    char *fname_cfg;
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
    "%s -x <bootimg> [<bootimg.cfg> [<kernel> [<ramdisk> [<secondstage>]]]]\n"
    "    extract objects from boot image:\n"
    "    - config file (bootimg.cfg)\n"
    "    - kernel image (zImage)\n"
    "    - ramdisk image (initrd.img)\n"
    "    - second stage image (stage2.img)\n"
    "\n"
    "%s -u <bootimg> [-c \"param=value\"] [-f <bootimg.cfg>] [-k <kernel>] [-r <ramdisk>] [-s <secondstage>]\n"
    "    update current boot image with objects given in command line\n"
    "    - header informations given in arguments (several can be provided)\n"
    "    - header informations given in config file\n"
    "    - kernel image\n"
    "    - ramdisk image\n"
    "    - second stage image\n"
    "\n"
    "%s --create <bootimg> [-c \"param=value\"] [-f <bootimg.cfg>] -k <kernel> -r <ramdisk> [-s <secondstage>]\n"
    "    create a new image from scratch.\n"
    "    arguments are the same as for -u.\n"
    "    kernel and ramdisk are mandatory.\n"
    "\n"
    "Config params:\n"
    "    bootsize = 0x1234                   - target size in bytes, if specified, image will always be this big (0 means ignore)\n"
    "    pagesize = 0x1234                   - Page size in bytes\n"
    "    kerneladdr = 0x1234                 - kernel load address\n"
    "    ramdiskaddr = 0x1234                - ramdisk load address\n"
    "    secondaddr = 0x1234                 - 2nd stage load address\n"
    "    tagsaddr = 0x1234                   - atags address\n"
    "    name = string without quotes        - name of the image, max 16 characters\n"
    "    cmdline = string without quotes     - cmdline, max 512 characters\n"
    ,libbootimg_version_str(), prog_name, prog_name, prog_name, prog_name, prog_name);
}

static int print_info(const char *path)
{
    struct bootimg img;
    if(libbootimg_init_load(&img, path) < 0)
    {
        fprintf(stderr, "Failed to load bootimg \"%s\"!\n", path);
        return 1;
    }

    printf ("\nAndroid Boot Image Info:\n\n");
    printf ("* file name = %s\n\n", path);

    printf ("* image size = %u bytes (%.2f MB)\n", img.size, (double)img.size/0x100000);
    printf ("  page size  = %u bytes\n\n", img.hdr.page_size);

    printf ("* Boot Name = \"%s\"\n\n", img.hdr.name);

    printf ("* kernel size       = %u bytes (%.2f MB)\n", img.hdr.kernel_size, (double)img.hdr.kernel_size/0x100000);
    printf ("  ramdisk size      = %u bytes (%.2f MB)\n", img.hdr.ramdisk_size, (double)img.hdr.ramdisk_size/0x100000);
    if (img.hdr.second_size)
        printf ("  second stage size = %u bytes (%.2f MB)\n", img.hdr.second_size, (double)img.hdr.second_size/0x100000);

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
    int i;
    for (i=0; i<8; i++)
        printf ("0x%08x ", img.hdr.id[i]);
    printf ("\n\n");

    libbootimg_destroy(&img);
    return 0;
}

static int extract_bootimg(struct bbootimg_info *i)
{
    int res = libbootimg_init_load(&i->img, i->fname_img);
    if(res < 0)
    {
        fprintf(stderr, "Failed to load boot image (%s)!\n", strerror(-res));
        return -res;
    }

    const char *cfg = i->fname_cfg ? i->fname_cfg : "bootimg.cfg";
    printf("writing boot image config in %s\n", cfg);
    res = libbootimg_write_config(&i->img, cfg);
    if(res < 0)
    {
        fprintf(stderr, "Failed to write bootimg cfg (%s)!\n", strerror(-res));
        return -res;
    }

    const char *kernel = i->fname_kernel ? i->fname_kernel : "zImage";
    printf("extracting kernel in %s\n", kernel);
    res = libbootimg_dump_kernel(&i->img, kernel);
    if(res < 0)
    {
        fprintf(stderr, "Failed to extract kernel (%s)!\n", strerror(-res));
        return -res;
    }

    const char *ramdisk = i->fname_ramdisk ? i->fname_ramdisk : "initrd.img";
    printf("extracting ramdisk in %s\n", ramdisk);
    res = libbootimg_dump_ramdisk(&i->img, ramdisk);
    if(res < 0)
    {
        fprintf(stderr, "Failed to extract ramdisk (%s)!\n", strerror(-res));
        return -res;
    }

    if(i->img.hdr.second_size > 0)
    {
        const char *second = i->fname_second ? i->fname_second : "stage2.img";
        printf("extracting second stage in %s\n", second);
        res = libbootimg_dump_second(&i->img, second);
        if(res < 0)
        {
            fprintf(stderr, "Failed to extract second stage (%s)!\n", strerror(-res));
            return -res;
        }
    }

    libbootimg_destroy(&i->img);
    return 0;
}

static int copy_file(const char *src, const char *dst)
{
    FILE *in = fopen(src, "r");
    if(!in)
    {
        fprintf(stderr, "Failed to open src file!\n");
        return -1;
    }

    FILE *out = fopen(dst, "w");
    if(!out)
    {
        fclose(in);
        fprintf(stderr, "Failed to open dst file!\n");
        return -1;
    }

    int res = -1;
#define BUFF_SIZE (512*1024)
    char *buff = malloc(BUFF_SIZE);
    size_t read;

    while((read = fread(buff, 1, BUFF_SIZE, in)) > 0)
    {
        if(fwrite(buff, 1, read, out) != read)
        {
            fprintf(stderr, "Failed to write data to dst file!\n");
            goto exit;
        }
    }

    res = 0;
exit:
    free(buff);
    fclose(in);
    fclose(out);
    return res;
}

static int update_bootimg(struct bbootimg_info *i)
{
    int res = -1;
    char *tmpname = malloc(strlen(i->fname_img)+sizeof(".new"));
    strcpy(tmpname, i->fname_img);
    strcat(tmpname, ".new");

    if(i->fname_cfg)
    {
        int line = -1;
        printf("reading config file %s\n", i->fname_cfg);
        res = libbootimg_load_config(&i->img, i->fname_cfg, &line);
        if(res < 0)
        {
            res = -res;
            fprintf(stderr, "Failed to load config (%s), error on line %d!\n", strerror(res), line);
            goto exit;
        }
    }

    if(i->fname_kernel)
    {
        printf("reading kernel from %s\n", i->fname_kernel);
        res = libbootimg_load_kernel(&i->img, i->fname_kernel);
        if(res < 0)
        {
            res = -res;
            fprintf(stderr, "Failed to load kernel (%s)!\n", strerror(res));
            goto exit;
        }
    }

    if(i->fname_ramdisk)
    {
        printf("reading ramdisk from %s\n", i->fname_ramdisk);
        res = libbootimg_load_ramdisk(&i->img, i->fname_ramdisk);
        if(res < 0)
        {
            res = -res;
            fprintf(stderr, "Failed to load ramdisk (%s)!\n", strerror(res));
            goto exit;
        }
    }

    if(i->fname_second)
    {
        printf("reading second stage from %s\n", i->fname_second);
        res = libbootimg_load_second(&i->img, i->fname_second);
        if(res < 0)
        {
            res = -res;
            fprintf(stderr, "Failed to load second stage (%s)!\n", strerror(res));
            goto exit;
        }
    }

    printf("Writing Boot Image %s\n", i->fname_img);
    res = libbootimg_write_img(&i->img, tmpname);
    if(res < 0)
    {
        res = -res;
        fprintf(stderr, "Failed to create boot image (%s)!\n", strerror(res));
        goto exit;
    }

    copy_file(tmpname, i->fname_img);

exit:
    remove(tmpname);
    free(tmpname);
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
            if(!i->fname_kernel || !i->fname_ramdisk)
            {
                fprintf(stderr, "You have to specify both ramdisk and kernel to create boot image!\n");
                return EINVAL;
            }
            return update_bootimg(i);
        }
    }
    return EINVAL;
}

static int load_bootimg(struct bootimg *b, const char *path)
{
    int res = libbootimg_init_load(b, path);
    if(res < 0)
    {
        fprintf(stderr, "Failed to load boot image (%s)!", strerror(-res));
        return -res;
    }
    return 0;
}

int main(int argc, char *argv[])
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

        if(i+1 >= argc)
            continue;

        if(strcmp("-i", argv[i]) == 0)
            return print_info(argv[i+1]);

        // actions
        if(strcmp("-x", argv[i]) == 0)
        {
            info.act = ACT_EXTRACT;
            info.fname_img = argv[++i];

            if(++i < argc)
                info.fname_cfg = argv[i];
            if(++i < argc)
                info.fname_kernel = argv[i];
            if(++i < argc)
                info.fname_ramdisk = argv[i];
            if(++i < argc)
                info.fname_second = argv[i];
            break;
        }
        else if(strcmp("-u", argv[i]) == 0)
        {
            info.act = ACT_UPDATE;
            info.fname_img = argv[++i];
            if(load_bootimg(&info.img, info.fname_img) != 0)
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
            if(libbootimg_load_config_line(&info.img, argv[++i]) < 0)
            {
                fprintf(stderr, "Invalid config option \"%s\"\n\n", argv[i]);
                goto exit_help;
            }
        }
        else if(strcmp("-f", argv[i]) == 0)
            info.fname_cfg = argv[++i];
        else if(strcmp("-k", argv[i]) == 0)
            info.fname_kernel = argv[++i];
        else if(strcmp("-r", argv[i]) == 0)
            info.fname_ramdisk = argv[++i];
        else if(strcmp("-s", argv[i]) == 0)
            info.fname_second = argv[++i];
        else
        {
            fprintf(stderr, "Unknown argument: %s\n\n", argv[i]);
            goto exit_help;
        }
    }

    if(info.act != ACT_HELP)
        return execute_action(&info);

exit_help:
    libbootimg_destroy(&info.img);
    print_help(argv[0]);
    return EINVAL;
}
