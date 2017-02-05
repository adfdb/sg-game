/*  
    Copyright (C) 2016 adfdb

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.  
*/
#include <stdio.h>
#include <png.h>
#include <jpeglib.h>
#include <stdarg.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define VERSION "001"

/*
   0-3     .. the total length of the embedded message, including these 4 bytes
   4-6     .. version
   7       .. 'p' for plain, 'e' for encoded message
   8       .. message type, 't' text (print to stdout) or 'f' file (save to file)
   9       .. length of the file name, including the terminating character \0
   10-     .. file name
           .. embedded message
*/
const int iver = 4, ienc = 7, itype = 8, iflen = 9, imsg = 10;

#ifndef kroundup32
#define kroundup32(x) (--(x), (x)|=(x)>>1, (x)|=(x)>>2, (x)|=(x)>>4, (x)|=(x)>>8, (x)|=(x)>>16, ++(x))
#endif

#define hts_expand(type_t, n, m, ptr) if ((n) > (m)) { \
    (m) = (n); kroundup32(m); \
    (ptr) = (type_t*)realloc((ptr), (m) * sizeof(type_t)); \
}

#define MODE_ENC 1
#define MODE_DEC 2

typedef struct
{
    uint8_t *msg;
    uint32_t mode, nmsg, mmsg;
    char *input_fname, *output_fname, *embed_secret;
    char *password;
}
args_t;

static void error(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
    exit(-1);
}

static inline int endian_is_big(void)
{
    long one= 1;
    return !(*((char *)(&one)));
}

#if HAVE_SSL
static void init_key(char *password, uint8_t key[32], uint8_t ivec[16])
{
    // N.B. this is wrong, iv shouldn't be fixed, but random and embedded in the message.
    // However, for this toy application we don't really care
    int i, len = strlen(password);
    memset(key,0,32);
    for (i=0; i<32 && i<len; i++) key[i]  = password[i];
    for (i=0; i<16; i++) ivec[i] = i;
}
#endif

static void read_text(args_t *args)
{
    char *fname = NULL;
    size_t len = 0, i;
    ssize_t nread;

    fname = args->embed_secret ? args->embed_secret : "-";
    char *end = fname + strlen(fname);
    char *beg = end;
    while ( beg > fname && *beg != '/' && *beg!='\\' && end - beg + 1 < 255 ) beg--;
    if ( *beg=='/' || *beg=='\\' ) beg++;
    uint8_t fname_len = end - beg + 1;

    uint8_t type = 'f';
    if ( !args->embed_secret && isatty(fileno((FILE *)stdin)) )
    {
        type = 't';
        fprintf(stderr, "Type the message, then press enter and type CTRL+d to finish:\n");
    }

    hts_expand(uint8_t, fname_len + 7, args->mmsg, args->msg);
    args->nmsg = 4;
    memcpy(args->msg+args->nmsg, VERSION, 3); args->nmsg += 3;
    args->msg[args->nmsg++] = args->password ? 'e' : 'p';
    args->msg[args->nmsg++] = type;
    args->msg[args->nmsg++] = fname_len;
    memcpy(args->msg + args->nmsg, beg, fname_len);
    args->nmsg += fname_len;

    FILE *fp = strcmp("-",fname) ? fopen(fname,"r") : stdin;
    if ( !fp ) error("Error opening %s: %s\n", fname,strerror(errno));

    if ( type=='t' )
    {
        char *line = NULL;
        while ( (nread = getline(&line, &len, fp)) > 0 ) 
        {
            hts_expand(uint8_t, args->nmsg+nread, args->mmsg, args->msg);
            for (i=0; i<nread; i++)
            {
                // 9,10: \t,\n
                if ( (uint8_t)line[i]<9 ) continue;
                if ( (uint8_t)line[i]>10 && (uint8_t)line[i]<32 ) continue;
                if ( (uint8_t)line[i]>127 ) continue;
                args->msg[args->nmsg++] = line[i];
            }
        }
        free(line);
    }
    else
    {
        hts_expand(uint8_t, args->nmsg+1024, args->mmsg, args->msg);
        while ( (nread = fread(args->msg + args->nmsg, 1, 1024, fp)) > 0 )
        {
            args->nmsg += nread;
            hts_expand(uint8_t, args->nmsg+1024, args->mmsg, args->msg);
        }
    }
    if ( strcmp("-",fname) && fclose(fp)!=0 ) error("Error closing %s\n", fname);

    if ( args->password )
    {
#if HAVE_SSL
        // encrypt message
        int len;
        uint8_t key[32], ivec[16];
        init_key(args->password, key, ivec);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if ( !ctx ) { ERR_print_errors_fp(stderr); error("Could not initialize AES encryption\n"); }
        uint8_t *buf = (uint8_t*) malloc(args->nmsg + 16);
        if ( EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, ivec) != 1 ) { ERR_print_errors_fp(stderr); error("Could not initialize AES encryption..\n"); }
        if ( EVP_EncryptUpdate(ctx, buf, &len, args->msg+itype, args->nmsg-itype) != 1 ) { ERR_print_errors_fp(stderr); error("Incorrect password\n"); }
        int ciphertext_len = len;
        if ( EVP_EncryptFinal_ex(ctx, buf + len, &len) != 1 ) { ERR_print_errors_fp(stderr); error("Could not initialize AES encryption\n"); }
        ciphertext_len += len;
        EVP_CIPHER_CTX_free(ctx);
        int aes_padding = ciphertext_len - args->nmsg + itype;
        args->nmsg += aes_padding;
        hts_expand(uint8_t, args->nmsg, args->mmsg, args->msg);
        memcpy(args->msg+itype, buf, args->nmsg-itype);
        free(buf);
#else
        error("Not compiled with -DHAVE_SSL, cannot use -p\n");
#endif
    }

    uint8_t *ptr = (uint8_t*) &args->nmsg;
    for (i=0; i<4; i++) args->msg[i] = endian_is_big() ? ptr[3-i] : ptr[i];

    // keep valgrind happy
    if ( args->nmsg%8 )
    {
        int pad = 8 - (args->nmsg % 8);
        hts_expand(uint8_t, args->nmsg+pad, args->mmsg, args->msg);
        for (i=0; i<pad; i++) args->msg[args->nmsg+i] = 0;
    }
}
static uint32_t get_text_length(uint8_t *msg)
{
    int i;
    uint32_t msg_len;
    uint8_t *ptr = (uint8_t*) &msg_len;
    for (i=0; i<4; i++) ptr[endian_is_big() ? 3-i : i] = msg[i];
    return msg_len;
}
static void parse_text(args_t *args, char **fname, uint32_t *nmsg, uint8_t **msg)
{
    uint32_t msg_len = get_text_length(args->msg);

    if ( memcmp(args->msg+iver,VERSION,3) )
        error("Error: No secret found or incompatible program/file versions: %c%c%c vs %s\n",
                (char)args->msg[iver],(char)args->msg[iver+1],(char)args->msg[iver+2],VERSION);

    if ( args->msg[ienc] == 'e' )
    {
        // decrypt
        if ( !args->password ) error("Encrypted message, run with -p\n");
#if HAVE_SSL
        int len;
        uint8_t key[32], ivec[16];
        init_key(args->password, key, ivec);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if ( !ctx ) { ERR_print_errors_fp(stderr); error("Error: Could not initialize AES decryption\n"); }
        uint8_t *buf = (uint8_t*) malloc(msg_len);
        if ( EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, ivec) != 1 ) { ERR_print_errors_fp(stderr); error("Error: Could not initialize AES decryption.\n"); }
        if ( EVP_DecryptUpdate(ctx, buf, &len, args->msg+itype, msg_len-itype) != 1 ) { ERR_print_errors_fp(stderr); error("Error: AES decryption failed. An incorrect key perhpas..?\n"); }
        int plaintext_len = len;
        if ( EVP_DecryptFinal_ex(ctx, buf + len, &len) != 1 ) { ERR_print_errors_fp(stderr); error("Error: AES decryption failed. An incorrect key perhpas?\n"); }
        plaintext_len += len; 
        EVP_CIPHER_CTX_free(ctx);
        int aes_padding =  msg_len - itype - plaintext_len;
        msg_len -= aes_padding;
        memcpy(args->msg+itype, buf, msg_len);
        free(buf);
#else
        error("Not compiled with -DHAVE_SSL, cannot use -p\n");
#endif
    }
    else if ( args->msg[ienc] != 'p' ) error("No embedded message found in %s\n", args->input_fname);

    uint8_t raw_fname_len = args->msg[iflen];
    char *raw_fname = (char*)(args->msg + imsg);

    *nmsg = msg_len - imsg - raw_fname_len;
    *msg  = args->msg + imsg + raw_fname_len;

    if ( !strcmp("-",raw_fname) ) { *fname = NULL; return; }
    char *suffix = raw_fname + raw_fname_len;
    while ( suffix > raw_fname && *suffix!='.' ) suffix--;
    int prefix_len = args->output_fname ? strlen(args->output_fname) : 0;
    char *tmp = (char*) malloc(raw_fname_len + prefix_len + 10);
    *fname = tmp;
    if ( prefix_len ) memcpy(tmp, args->output_fname, prefix_len);
    memcpy(tmp+prefix_len, raw_fname, raw_fname_len);
    tmp[prefix_len + raw_fname_len] = 0;
    int i = 0;
    while (1)
    {
        struct stat buffer;   
        if ( stat(tmp, &buffer)!=0 ) return;
        sprintf(tmp+prefix_len+(suffix-raw_fname),"-%d%s",i++,suffix);
    }
}

static void read_password(args_t *args)
{
    if ( !args->password ) return;
    if ( strcmp("-",args->password) )
    {
        args->password = strdup(args->password);
        return;
    }

    fprintf(stderr, "Type the password: ");

    char *line = NULL;
    size_t len = 0;
    ssize_t nread;

    FILE *fp = stdin;
    while ( (nread = getline(&line, &len, fp)) > 0 ) 
    {
        line[nread-1] = 0;
        args->password = line;
        break;
    }
}

static void write_png(char *fname, uint8_t *buffer, int width, int height)
{
    FILE *fp = fopen(fname, "wb");
    if ( !fp )
        error( "Error: can't open %s .. %s\n", fname,strerror(errno));

    png_structp png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL,NULL,NULL);
    if ( !png_ptr )
        error("Error: png_create_write_structpng_create_write_struct failed\n");

    png_infop info_ptr = png_create_info_struct(png_ptr);
    png_set_IHDR(png_ptr, info_ptr, width, height,
            8, PNG_COLOR_TYPE_RGB, PNG_INTERLACE_NONE,
            PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);

    png_init_io(png_ptr, fp);
    png_write_info(png_ptr, info_ptr);

    int i;
    for (i=0; i<height; i++)
        png_write_row(png_ptr, buffer + i*width*3); 

    png_write_end(png_ptr, info_ptr);
    png_destroy_write_struct(&png_ptr, &info_ptr);
    png_destroy_write_struct(&png_ptr, &info_ptr);

    if ( fclose(fp)!=0 )
        error("Error closing %s\n", fname);
}

static uint8_t *read_png(char *fname, uint32_t *width, uint32_t *height)
{
    png_image image;
    memset(&image, 0, (sizeof image));
    image.version = PNG_IMAGE_VERSION;

    if ( png_image_begin_read_from_file(&image, fname) == 0 )
        error("error: %s .. %s\n", fname, image.message);

    image.format = PNG_FORMAT_RGB;
    png_bytep buffer = malloc(PNG_IMAGE_SIZE(image));
    if ( !buffer )
        error("error: there is not enough memory to store the image in memory (%d bytes), can we be smarter about this? (we can)\n", PNG_IMAGE_SIZE(image));

    if ( png_image_finish_read(&image, NULL, buffer, 0, NULL) == 0 )
        error("error: %s .. %s\n", fname, image.message);

    *width  = image.width;
    *height = image.height;

    if ( (*width)*(*height)*3 != PNG_IMAGE_SIZE(image) ) error("%d*%d*3=%d vs %d\n",*width,*height,(*width)*(*height)*3,PNG_IMAGE_SIZE(image));

    return buffer;
}

static uint8_t *read_jpg(char *fname, uint32_t *width, uint32_t *height)
{
    FILE *fd = fopen(fname, "rb");
    if ( !fd )
        error("Error: cannot open %s\n", fname);

    struct jpeg_decompress_struct cinfo;
    struct jpeg_error_mgr jerr;

    cinfo.err = jpeg_std_error(&jerr);
    jpeg_create_decompress(&cinfo);
    jpeg_stdio_src(&cinfo, fd);
    jpeg_read_header(&cinfo, TRUE);
    jpeg_start_decompress(&cinfo);

    *width  = cinfo.output_width;
    *height = cinfo.output_height;
    uint8_t *out = (uint8_t *) malloc(cinfo.output_width*cinfo.output_height*3);
    if ( !out )
        error("Error: there is not enough memory to store the image in memory (%d bytes), can we be smarter about this? (we can)\n", cinfo.output_width*cinfo.output_height*3);

    int row_stride = cinfo.output_width * cinfo.output_components;
    JSAMPARRAY buffer = (*cinfo.mem->alloc_sarray)((j_common_ptr) &cinfo, JPOOL_IMAGE, row_stride, 1);

    int y=0, i;
    while ( cinfo.output_scanline < cinfo.output_height )
    {
        jpeg_read_scanlines(&cinfo, buffer, 1);
        if ( cinfo.output_components==1 )
        {
            uint8_t *ptr = out + 3*y*cinfo.output_width;
            for (i=0; i<cinfo.output_width; i++)
            {
                ptr[0] = ptr[1] = ptr[2] = buffer[0][i];
                ptr += 3;
            }
        }
        else
            memcpy(out + 3*y*cinfo.output_width, buffer[0], row_stride);
        y++;
    }

    jpeg_destroy_decompress(&cinfo);
    if ( fclose(fd)!= 0 )
        error("Error closing %s\n", fname);

    return out;
}

static inline void ebuf_encode(uint8_t *buf, uint8_t byte, uint32_t *ioff)
{
    int i;
    for (i=0; i<8; i++)
    {
        if ( byte & (1<<i) )
        {
            if ( buf[*ioff + i]%2 == 0 ) buf[*ioff + i] += buf[*ioff + i]==255 ? -1 : 1;    // bit on, set to odd
        }
        else
        {
            if ( buf[*ioff + i]%2 == 1 ) buf[*ioff + i] += buf[*ioff + i]==255 ? -1 : 1;    // bit off, set to even
        }
    }
    (*ioff) += 8;
}
static inline void ebuf_encode16(int16_t *buf, uint8_t byte)
{
    int i;
    for (i=0; i<8; i++)
    {
        int change = 0;
        if ( byte & (1<<i) )
        {
            if ( (uint16_t)buf[i]%2 == 0 ) change = 1;  // bit is on, set to odd
        }
        else
        {
            if ( (uint16_t)buf[i]%2 == 1 ) change = 1;  // bit off, set to even
        }
        if ( change )
        {
            if ( buf[i]==32767 ) buf[i] = 32766;
            else if ( buf[i]==-32768 ) buf[i] = -32767;
            else buf[i] += (rand()&2) - 1;
        }
    }
}
static inline uint8_t ebuf_decode(uint8_t *buf, uint32_t *ioff)
{
    int i;
    uint8_t byte = 0;
    for (i=0; i<8; i++)
        if ( buf[*ioff + i]%2 == 1 ) byte |= 1<<i;
    (*ioff) += 8;
    return byte;
}
static inline uint8_t ebuf_decode16(int16_t *buf)
{
    int i;
    uint8_t byte = 0;
    for (i=0; i<8; i++)
        if ( (uint16_t)buf[i]%2 == 1 ) byte |= 1<<i;
    return byte;
}

static void embed_in_png(args_t *args)
{
    uint32_t width, height;
    uint8_t *buffer;
    if ( !strcasecmp(".png",args->input_fname + strlen(args->input_fname) - 4 ) ) 
        buffer = read_png(args->input_fname, &width, &height);
    else
        buffer = read_jpg(args->input_fname, &width, &height);

    uint32_t i = 0, ioff = 0, buf_len = width*height*3;
    while ( i < args->nmsg && ioff < buf_len )
    {
        ebuf_encode(buffer, args->msg[i], &ioff);
        i++;
    }
    if ( i < args->nmsg )  error("The secret is %d bytes too big to embed in %s\n", args->nmsg - i, args->input_fname);
    write_png(args->output_fname, buffer, width, height);
    free(buffer);
}
static void embed_in_jpg(args_t *args)
{
    struct jpeg_decompress_struct srcinfo;
    struct jpeg_compress_struct dstinfo;
    struct jpeg_error_mgr jsrcerr, jdsterr;
    jvirt_barray_ptr * src_coef_arrays;
    jvirt_barray_ptr * dst_coef_arrays;

    srcinfo.err = jpeg_std_error(&jsrcerr);
    jpeg_create_decompress(&srcinfo);
    dstinfo.err = jpeg_std_error(&jdsterr);
    jpeg_create_compress(&dstinfo);

    FILE *input_file = fopen(args->input_fname, "rb");
    if ( !input_file ) error( "Error: can't open %s .. %s\n", args->input_fname,strerror(errno));
    FILE *output_file = fopen(args->output_fname, "wb");
    if ( !output_file ) error( "Error: can't open %s .. %s\n", args->output_fname,strerror(errno));

    jpeg_stdio_src(&srcinfo, input_file);
    (void) jpeg_read_header(&srcinfo, TRUE);
    src_coef_arrays = jpeg_read_coefficients(&srcinfo);

    if ( DCTSIZE!=8 ) error("fixme: assumption failed, DCTSIZE=%d\n",DCTSIZE);
    int i,j,k,l, idst = ienc, jmsg = 0, ncomp = srcinfo.num_components;
    int navail = 0;
    for (i=0; i<ncomp; i++)
    {
        int wd = srcinfo.comp_info[i].width_in_blocks;
        int ht = srcinfo.comp_info[i].height_in_blocks;
        navail += wd*ht*DCTSIZE;
    }
    float nstep = (float)navail / args->nmsg;
    for (i=0; i<ncomp; i++)
    {
        int wd = srcinfo.comp_info[i].width_in_blocks;
        int ht = srcinfo.comp_info[i].height_in_blocks;
        for (j=0; j<ht; j++)
        {
            JBLOCKARRAY ptr = (srcinfo.mem->access_virt_barray)((j_common_ptr)&srcinfo, src_coef_arrays[i], j, (JDIMENSION)1, FALSE);
            for (k=0; k<wd; k++)
            {
                for (l=0; l<DCTSIZE2; l+=DCTSIZE)
                {
                    if ( jmsg >= ienc && (idst++) < jmsg*nstep ) continue;
                    ebuf_encode16(&ptr[0][k][l], args->msg[jmsg++]);
                    if ( jmsg >= args->nmsg ) goto done;
                }
            }
        }
    }
    if ( jmsg < args->nmsg ) error("The secret is %d bytes too big to embed in %s\n", args->nmsg - jmsg, args->input_fname);
done:
    jpeg_copy_critical_parameters(&srcinfo, &dstinfo);
    dst_coef_arrays = src_coef_arrays;
    jpeg_stdio_dest(&dstinfo, output_file);
    jpeg_write_coefficients(&dstinfo, dst_coef_arrays);

    jpeg_finish_compress(&dstinfo);
    jpeg_destroy_compress(&dstinfo);
    (void) jpeg_finish_decompress(&srcinfo);
    jpeg_destroy_decompress(&srcinfo);

    if ( fclose(input_file)!=0 ) error("Error closing %s\n", args->input_fname);
    if ( fclose(output_file)!=0 ) error("Error closing %s\n", args->output_fname);
    
    if ( jsrcerr.num_warnings + jdsterr.num_warnings ) fprintf(stderr,"%d warnings\n", (int)(jsrcerr.num_warnings + jdsterr.num_warnings));
}
static void embed_message(args_t *args)
{
    if ( !strcasecmp(".png",args->output_fname + strlen(args->output_fname) - 4 ) ) 
        embed_in_png(args);
    else
    {
        if ( !strcasecmp(".png",args->input_fname + strlen(args->input_fname) - 4 ) ) error("Expected JPEG file with -e if -o is\n");
        embed_in_jpg(args);
    }
}
static void retrieve_from_png(args_t *args)
{
    png_image image;
    memset(&image, 0, (sizeof image));
    image.version = PNG_IMAGE_VERSION;

    if ( png_image_begin_read_from_file(&image, args->input_fname) == 0 )
        error("error: %s .. %s\n", args->input_fname, image.message);

    image.format = PNG_FORMAT_RGB;
    png_bytep buffer = malloc(PNG_IMAGE_SIZE(image));
    if ( !buffer )
        error("error: there is not enough memory to store the image in memory (%d byts), can we be smarter about this? (we can)\n", PNG_IMAGE_SIZE(image));

    if ( png_image_finish_read(&image, NULL, buffer, 0, NULL) == 0 )
        error("error: %s .. %s\n", args->input_fname, image.message);

    hts_expand(uint8_t, 4, args->mmsg, args->msg);
    uint32_t ioff = 0, msg_len = 0;
    while ( ioff < PNG_IMAGE_SIZE(image) )
    {
        args->msg[args->nmsg++] = ebuf_decode(buffer, &ioff);
        if ( args->nmsg==4 )
        {
            msg_len = get_text_length(args->msg);
            int pad = 8 - (msg_len % 8);
            hts_expand(uint8_t, msg_len+pad, args->mmsg, args->msg);
        }
        if ( args->nmsg > 4 && args->nmsg==msg_len ) break;
    }
    if ( args->nmsg != msg_len ) error("Error reading %d embedded bytes from %s\n", msg_len, args->input_fname);
    png_image_free(&image);

    char *fname = NULL;
    uint32_t nmsg;
    uint8_t *msg;
    parse_text(args, &fname, &nmsg, &msg);
    if ( fname ) fprintf(stderr,"Saving to %s\n", fname);
    FILE *fp = fname ? fopen(fname,"wb") : stdout;
    if ( !fp ) error( "Error: cannot open %s .. %s\n", fname,strerror(errno));
    if ( fwrite(msg, 1, nmsg, fp) != nmsg ) error("Could not write %d bytes\n", nmsg);
    if ( fname && fclose(fp)!=0 ) error("Error closing %s\n", fname);
    free(fname);

    free(buffer);
}
static void retrieve_from_jpg(args_t *args)
{
    struct jpeg_decompress_struct srcinfo;
    struct jpeg_error_mgr jsrcerr;
    jvirt_barray_ptr * src_coef_arrays;

    srcinfo.err = jpeg_std_error(&jsrcerr);
    jpeg_create_decompress(&srcinfo);

    FILE *input_file = fopen(args->input_fname, "rb");
    if ( !input_file ) error( "Error: can't open %s .. %s\n", args->input_fname,strerror(errno));

    jpeg_stdio_src(&srcinfo, input_file);
    (void) jpeg_read_header(&srcinfo, TRUE);
    src_coef_arrays = jpeg_read_coefficients(&srcinfo);

    if ( DCTSIZE!=8 ) error("fixme: assumption failed, DCTSIZE=%d\n",DCTSIZE);

    int i,j,k,l, idst = ienc, ncomp = srcinfo.num_components;
    float nstep = 0;
    uint32_t msg_len = 0;
    for (i=0; i<ncomp; i++)
    {
        int wd = srcinfo.comp_info[i].width_in_blocks;
        int ht = srcinfo.comp_info[i].height_in_blocks;
        for (j=0; j<ht; j++)
        {
            JBLOCKARRAY ptr = (srcinfo.mem->access_virt_barray)((j_common_ptr)&srcinfo, src_coef_arrays[i], j, (JDIMENSION)1, FALSE);
            for (k=0; k<wd; k++)
            {
                for (l=0; l<DCTSIZE2; l+=DCTSIZE)
                {
                    if ( args->nmsg >= ienc && (idst++) < args->nmsg*nstep ) continue;
                    hts_expand(uint8_t, args->nmsg+1, args->mmsg, args->msg);
                    args->msg[args->nmsg++] = ebuf_decode16(&ptr[0][k][l]);
                    if ( args->nmsg==iver ) 
                    {
                        msg_len = get_text_length(args->msg);
                        int navail = 0, x;
                        for (x=0; x<ncomp; x++)
                        {
                            int wd = srcinfo.comp_info[x].width_in_blocks;
                            int ht = srcinfo.comp_info[x].height_in_blocks;
                            navail += wd*ht*DCTSIZE;
                        }
                        nstep = (float)navail / msg_len;
                    }
                    if ( args->nmsg > iver && args->nmsg==msg_len ) goto done;
                }
            }
        }
    }
done:
    (void) jpeg_finish_decompress(&srcinfo);
    jpeg_destroy_decompress(&srcinfo);
    if ( fclose(input_file)!=0 ) error("Error closing %s\n", args->input_fname);

    char *fname = NULL;
    uint32_t nmsg;
    uint8_t *msg;
    parse_text(args, &fname, &nmsg, &msg);
    if ( fname ) fprintf(stderr,"Saving to %s\n", fname);
    FILE *fp = fname ? fopen(fname,"wb") : stdout;
    if ( !fp ) error( "Error: cannot open %s .. %s\n", fname,strerror(errno));
    fwrite(msg, 1, nmsg, fp);
    if ( fname && fclose(fp)!=0 ) error("Error closing %s\n", fname);
    free(fname);
}
static void retrieve_message(args_t *args)
{
    if ( !strcasecmp(".png",args->input_fname + strlen(args->input_fname) - 4 ) ) 
        retrieve_from_png(args);
    else
        retrieve_from_jpg(args);
}
static void usage(void)
{
    fprintf(stderr, "\n");
    fprintf(stderr, "About: Encode plain text or an arbitrary file into an image\n");
    fprintf(stderr, "Usage: sg-game [OPTIONS]\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "   -e, --encode <file>          PNG/JPG container\n");
    fprintf(stderr, "   -d, --decode <file>          decode the embedded text or file\n");
    fprintf(stderr, "   -o, --output <file|prefix>   output PNG/JPG file (with -e) or output file prefix (with -d)\n");
    fprintf(stderr, "   -p, --password <text>        protect with password, \"-\" to read from stdin\n");
    fprintf(stderr, "   -s, --embed-secret <file>    file to embed in the image\n");
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "   # Embed file, then retrieve\n");
    fprintf(stderr, "   sg-game -e container.jpg -o encoded.png -s file.dat\n");
    fprintf(stderr, "   sg-game -d encoded.png -o prefix\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "   # Embed text, then retrieve\n");
    fprintf(stderr, "   sg-game -e container.jpg -o encoded.jpg\n");
    fprintf(stderr, "   <type message when prompted>\n");
    fprintf(stderr, "   sg-game -d encoded.jpg\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "   # Embed and retrieve text, password protected\n");
    fprintf(stderr, "   sg-game -e container.jpg -o encoded.png -s file.dat -p password\n");
    fprintf(stderr, "   sg-game -d encoded.png -p password\n");
    fprintf(stderr, "\n");
    exit(-1);
}

int main(int argc, char *argv[])
{
    if ( argc==1 ) usage();

    int c;
    args_t *args = calloc(1,sizeof(args_t));
    static struct option loptions[] = 
    {
        {"encode",1,0,'e'},
        {"decode",1,0,'d'},
        {"embed-secret",1,0,'s'},
        {"output",1,0,'o'},
        {"password",1,0,'p'},
        {"help",0,0,'h'}
    };
    while ((c = getopt_long(argc, argv, "h?e:d:s:o:p:", loptions, NULL)) >= 0) 
    {
        switch (c) 
        {
            case 'e': args->mode = MODE_ENC; args->input_fname = optarg; break;
            case 'd': args->mode = MODE_DEC; args->input_fname = optarg; break;
            case 'o': args->output_fname = optarg; break;
            case 'p': args->password = optarg; break;
            case 's': args->embed_secret = optarg; break;
            default: usage();
        }
    }
    if ( !args->mode ) error("Expected one of -e or -d options.\n");
    if ( !args->input_fname ) error("Missing the -i, --input-image option.\n");
    
    read_password(args);
    if ( args->mode==MODE_ENC )
    {
        read_text(args);
        embed_message(args);
    }
    else
        retrieve_message(args);

    free(args->msg);
    free(args->password);
    free(args);
    return 0;
}


