#ifndef __ZLIB_GZIP_H_
#define __ZLIB_GZIP_H_

#if defined(MSDOS) || defined(OS2) || defined(WIN32) || defined(__CYGWIN__)
#  include <fcntl.h>
#  include <io.h>
#  define SET_BINARY_MODE(file) setmode(fileno(file), O_BINARY)
#else
#  define SET_BINARY_MODE(file)
#endif


#ifdef __cplusplus
extern "C" {
#endif

/* 
 *  def and inf function are got from http://www.zlib.net/zpipe.c
 *  def function generate dest file, but dest file is not gzip format.
 *	gz_compress function can generate gzip format file.
 *
 *	if you want to get gzip format, need do these:
 *	1. write gzheader in file header
 *	2. use deflateInit2, not deflateInit
 *	3. append content to gz header
 *	4. append crc of sourc file to content
 *	5. append file length to crc
 */

int def(FILE *source, FILE *dest);
int inf(FILE *source, FILE *dest);

int gz_my(char * src_buf, unsigned int src_buf_len);
int gz_compress  (char ** dst_buf, unsigned int * dst_buf_len, char * src_buf, unsigned int src_buf_len);
int gz_decompress(char ** dst_buf, unsigned int * dst_buf_len, char * src_buf, unsigned int src_buf_len);

int gz_uncompress_chunk_data(char ** dst_buf, unsigned int * dst_buf_len, char * src_buf, unsigned int src_buf_len);

void gz_free(void * v);
#ifdef __cplusplus
}
#endif
#endif
