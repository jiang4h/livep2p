#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "gzip.h"
#include "zlib.h"

//#define segment_size 1460  //largest tcp data segment  
#define CHUNK 16384

// reference: http://zlib.net/zlib_how.html
// reference: http://zlib.net/zpipe.c


/* Compress from file source to file dest until EOF on source.
   def() returns Z_OK on success, Z_MEM_ERROR if memory could not be
   allocated for processing, Z_STREAM_ERROR if an invalid compression
   level is supplied, Z_VERSION_ERROR if the version of zlib.h and the
   version of the library linked do not match, or Z_ERRNO if there is
   an error reading or writing the files. */
int def(FILE *source, FILE *dest)
{
    int ret, flush;
    unsigned have;
    z_stream strm;
    unsigned char in[CHUNK];
    unsigned char out[2*CHUNK];
	int level = Z_DEFAULT_COMPRESSION;

	SET_BINARY_MODE(source);
	SET_BINARY_MODE(dest);

    /* allocate deflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
	//strm.avail_in = 0;
	//strm.next_in  = Z_NULL;

    ret = deflateInit(&strm, level);
    if (ret != Z_OK)
        return ret;

    /* compress until end of file */
    do {
        strm.avail_in = fread(in, 1, CHUNK, source);
        if (ferror(source)) {
            (void)deflateEnd(&strm);
            return Z_ERRNO;
        }
        flush = feof(source) ? Z_FINISH : Z_NO_FLUSH;
        strm.next_in = in;

        /* run deflate() on input until output buffer not full, finish
           compression if all of source has been read in */
        do {
            strm.avail_out = sizeof(out);
            strm.next_out = out;
            ret = deflate(&strm, flush);    /* no bad return value */
            assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
            have = strm.next_out - out;//CHUNK - strm.avail_out;
            if (fwrite(out, 1, have, dest) != have || ferror(dest)) {
                (void)deflateEnd(&strm);
                return Z_ERRNO;
            }
        } while (strm.avail_out == 0);
        assert(strm.avail_in == 0);     /* all input will be used */

        /* done when last data in file processed */
    } while (flush != Z_FINISH);
    assert(ret == Z_STREAM_END);        /* stream will be complete */

    /* clean up and return */
    (void)deflateEnd(&strm);
    return Z_OK;
}

/* Decompress from file source to file dest until stream ends or EOF.
   inf() returns Z_OK on success, Z_MEM_ERROR if memory could not be
   allocated for processing, Z_DATA_ERROR if the deflate data is
   invalid or incomplete, Z_VERSION_ERROR if the version of zlib.h and
   the version of the library linked do not match, or Z_ERRNO if there
   is an error reading or writing the files. */
int inf(FILE *source, FILE *dest)
{
    int ret;
    unsigned have;
    z_stream strm;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];

    /* allocate inflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit(&strm);
    if (ret != Z_OK)
        return ret;

    /* decompress until deflate stream ends or end of file */
    do {
        strm.avail_in = fread(in, 1, CHUNK, source);
        if (ferror(source)) {
            (void)inflateEnd(&strm);
            return Z_ERRNO;
        }
        if (strm.avail_in == 0)
            break;
        strm.next_in = in;

        /* run inflate() on input until output buffer not full */
        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;
            ret = inflate(&strm, Z_NO_FLUSH);
            assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
            switch (ret) {
            case Z_NEED_DICT:
                ret = Z_DATA_ERROR;     /* and fall through */
            case Z_DATA_ERROR:
            case Z_MEM_ERROR:
                (void)inflateEnd(&strm);
                return ret;
            }
            have = CHUNK - strm.avail_out;
            if (fwrite(out, 1, have, dest) != have || ferror(dest)) {
                (void)inflateEnd(&strm);
                return Z_ERRNO;
            }
        } while (strm.avail_out == 0);

        /* done when inflate() says it's done */
    } while (ret != Z_STREAM_END);

    /* clean up and return */
    (void)inflateEnd(&strm);
    return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}

int gz_my(char * src_buf, unsigned int src_buf_len)
{
    int ret, flush;
    unsigned have;
    z_stream strm;
    unsigned char in[CHUNK] = {0}, out[CHUNK] = {0};
    int copy_len = 0;
    int in_offset=0, out_offset=0;  
    int level = Z_DEFAULT_COMPRESSION;
    unsigned int crc = 0;
    //char gzheader[10] = { 0x1f, 0x8b, Z_DEFLATED, 0, 0, 0, 0, 0, 0, 3 };
	char * dst_buf = NULL;
	unsigned int dst_buf_len = 0;

    crc = crc32(0L, Z_NULL, 0);

    /* allocate deflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
	strm.avail_in = 0;
    strm.next_in = Z_NULL;

    ret = deflateInit2(&strm, level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK)
        return ret;

    do {
        copy_len = CHUNK < (src_buf_len - in_offset) ? CHUNK : src_buf_len - in_offset;
        strm.avail_in = copy_len;
        if ( strm.avail_in <= 0) {
            (void)deflateEnd(&strm);
            return Z_ERRNO;
        }

        memset(in, 0, sizeof(in));
        memcpy(in, src_buf + in_offset, copy_len);
        in_offset += copy_len;

        flush = in_offset >= src_buf_len ? Z_FINISH : Z_NO_FLUSH;
        strm.next_in = in;

        crc = crc32(crc, strm.next_in, strm.avail_in);

        /* run deflate() on input until output buffer not full, finish
           compression if all of source has been read in */
        do {
            strm.avail_out = sizeof(out);
            memset(out, 0, sizeof(out));
            strm.next_out = out;
            ret = deflate(&strm, flush);    /* no bad return value */
            assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
            have = strm.next_out - out;//CHUNK - strm.avail_out;
            out_offset += have;
        } while (strm.avail_out == 0);
        assert(strm.avail_in == 0);     /* all input will be used */

        /* done when last data in file processed */
    } while (flush != Z_FINISH);
    assert(ret == Z_STREAM_END);        /* stream will be complete */

    /* clean up and return */
    (void)deflateEnd(&strm);
    dst_buf_len = out_offset;

    // begin compress
    in_offset = out_offset = 0;
    dst_buf = malloc(sizeof(char) * dst_buf_len);
    memset(dst_buf, 0, dst_buf_len);
    //memcpy(dst_buf+out_offset, gzheader, sizeof(gzheader));
    //out_offset += sizeof(gzheader);

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
	strm.avail_in = 0;
	strm.next_in  = Z_NULL;

    ret = deflateInit2(&strm, level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK)
        return ret;

    do {
        copy_len = CHUNK < (src_buf_len - in_offset) ? CHUNK : src_buf_len - in_offset;
        strm.avail_in = copy_len;
        if ( strm.avail_in <= 0) {
            (void)deflateEnd(&strm);
            return Z_ERRNO;
        }

        memset(in, 0, sizeof(in));
        memcpy(in, src_buf + in_offset, copy_len);
        in_offset += copy_len;

        flush = in_offset >= src_buf_len ? Z_FINISH : Z_NO_FLUSH;
        strm.next_in = in;

        /* run deflate() on input until output buffer not full, finish
           compression if all of source has been read in */
        do {
            strm.avail_out = sizeof(out);
            memset(out, 0, sizeof(out));
            strm.next_out = out;
            ret = deflate(&strm, flush);    /* no bad return value */
            assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
            have = strm.next_out - out;//CHUNK - strm.avail_out;
            memcpy(dst_buf+out_offset, out, have);
            out_offset += have;
        } while (strm.avail_out == 0);
        assert(strm.avail_in == 0);     /* all input will be used */

        /* done when last data in file processed */
    } while (flush != Z_FINISH);
    assert(ret == Z_STREAM_END);        /* stream will be complete */

    /* clean up and return */
    (void)deflateEnd(&strm);

	// -------------------------------------------------------------
    // compressed over, content is in dst_buf, length is dst_buf_len
	{
		char *buffer = dst_buf;
		unsigned int length = dst_buf_len;
		z_stream strm2;
		unsigned int uncompress_length = 0;

		in_offset = out_offset = 0;  

		strm2.zalloc = Z_NULL;
		strm2.zfree = Z_NULL;
		strm2.opaque = Z_NULL;
		strm2.avail_in = 0;
		strm2.next_in = Z_NULL;

		ret = inflateInit2(&strm2, 47);
		if ( ret != Z_OK )
			return ret;

		do {
			copy_len = CHUNK < (length - in_offset) ? CHUNK : length - in_offset;
			strm.avail_in = copy_len;
			if (strm.avail_in == 0)
				break;

			memset(in, 0, sizeof(in));
			memcpy(in, buffer + in_offset, copy_len);
			in_offset += copy_len;
			strm.next_in = (Bytef*)in;

			do {
				strm.avail_out = CHUNK;
				memset(out, 0, sizeof(out));
				strm.next_out = (Bytef*)out;
				ret = inflate(&strm, Z_NO_FLUSH);
				assert(ret != Z_STREAM_ERROR);
				switch (ret) {
				case Z_NEED_DICT:
					ret = Z_DATA_ERROR;
				case Z_DATA_ERROR:
				case Z_MEM_ERROR:
					(void)inflateEnd(&strm);
					return ret;
				}
				have = CHUNK - strm.avail_out;
				out_offset += have;
			} while (strm.avail_out == 0);
		} while (ret != Z_STREAM_END);

		(void)inflateEnd(&strm);
		ret = Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
		uncompress_length = out_offset;


	}

    return Z_OK;
}




int gz_compress  (char ** dst_buf, unsigned int * dst_buf_len, char * src_buf, unsigned int src_buf_len)
{
    int ret, flush;
    unsigned have;
    z_stream strm;
    unsigned char in[CHUNK] = {0}, out[CHUNK] = {0};
    int copy_len = 0;
    int in_offset=0, out_offset=0;  
    int level = Z_DEFAULT_COMPRESSION;
    unsigned int crc = 0;
    char gzheader[10] = { 0x1f, 0x8b, Z_DEFLATED, 0, 0, 0, 0, 0, 0, 3 };

    crc = crc32(0L, Z_NULL, 0);

    /* allocate deflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.next_in = Z_NULL;

    ret = deflateInit2(&strm, level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK)
        return ret;

    do {
        copy_len = CHUNK < (src_buf_len - in_offset) ? CHUNK : src_buf_len - in_offset;
        strm.avail_in = copy_len;
        if ( strm.avail_in <= 0) {
            (void)deflateEnd(&strm);
            return Z_ERRNO;
        }

        memset(in, 0, sizeof(in));
        memcpy(in, src_buf + in_offset, copy_len);
        in_offset += copy_len;

        flush = in_offset >= src_buf_len ? Z_FINISH : Z_NO_FLUSH;
        strm.next_in = in;

        crc = crc32(crc, strm.next_in, strm.avail_in);

        /* run deflate() on input until output buffer not full, finish
           compression if all of source has been read in */
        do {
            strm.avail_out = sizeof(out);
            memset(out, 0, sizeof(out));
            strm.next_out = out;
            ret = deflate(&strm, flush);    /* no bad return value */
            assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
            have = strm.next_out - out;//CHUNK - strm.avail_out;
            out_offset += have;
        } while (strm.avail_out == 0);
        assert(strm.avail_in == 0);     /* all input will be used */

        /* done when last data in file processed */
    } while (flush != Z_FINISH);
    assert(ret == Z_STREAM_END);        /* stream will be complete */

    /* clean up and return */
    (void)deflateEnd(&strm);
    *dst_buf_len = sizeof(gzheader) + out_offset + sizeof(crc) + sizeof(src_buf_len);

    // begin compress
    in_offset = out_offset = 0;
    *dst_buf = malloc(sizeof(char) * (*dst_buf_len));
    memset(*dst_buf, 0, *dst_buf_len);
    memcpy(*dst_buf+out_offset, gzheader, sizeof(gzheader));
    out_offset += sizeof(gzheader);

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
	//strm.avail_in = 0;
	//strm.next_in  = Z_NULL;

    ret = deflateInit2(&strm, level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK)
        return ret;

    do {
        copy_len = CHUNK < (src_buf_len - in_offset) ? CHUNK : src_buf_len - in_offset;
        strm.avail_in = copy_len;
        if ( strm.avail_in <= 0) {
            (void)deflateEnd(&strm);
            return Z_ERRNO;
        }

        memset(in, 0, sizeof(in));
        memcpy(in, src_buf + in_offset, copy_len);
        in_offset += copy_len;

        flush = in_offset >= src_buf_len ? Z_FINISH : Z_NO_FLUSH;
        strm.next_in = in;

        /* run deflate() on input until output buffer not full, finish
           compression if all of source has been read in */
        do {
            strm.avail_out = sizeof(out);
            memset(out, 0, sizeof(out));
            strm.next_out = out;
            ret = deflate(&strm, flush);    /* no bad return value */
            assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
            have = strm.next_out - out;//CHUNK - strm.avail_out;
            memcpy((*dst_buf)+out_offset, out, have);
            out_offset += have;
        } while (strm.avail_out == 0);
        assert(strm.avail_in == 0);     /* all input will be used */

        /* done when last data in file processed */
    } while (flush != Z_FINISH);
    assert(ret == Z_STREAM_END);        /* stream will be complete */

    /* clean up and return */
    (void)deflateEnd(&strm);

    memcpy((*dst_buf)+out_offset, &crc, 4);
    out_offset += 4;
    memcpy((*dst_buf)+out_offset, &src_buf_len, 4);

    return Z_OK;
}


int gz_decompress(char ** dst_buf, unsigned int * dst_buf_len, char * src_buf, unsigned int src_buf_len)
{
	int ret, have;  
	int in_offset=0, out_offset=0;  
	int copy_len = 0;
	z_stream strm;  
	unsigned int in[CHUNK]={0}, out[CHUNK]={0};  

	strm.zalloc   = Z_NULL;  
	strm.zfree    = Z_NULL;  
	strm.opaque   = Z_NULL; 
	strm.avail_in = 0;
	strm.next_in  = Z_NULL;

	ret = inflateInit2(&strm, 47);  
	if(ret != Z_OK) {
		printf("inflateInit2 error:%d",ret);  
		return ret;  
	}

	do {
		copy_len = CHUNK < (src_buf_len - in_offset) ? CHUNK : src_buf_len - in_offset;
		strm.avail_in = copy_len;
		if (strm.avail_in == 0)
			break;

		memset(in, 0, sizeof(in));
		memcpy(in, src_buf + in_offset, copy_len);
		in_offset += copy_len;
		strm.next_in = (Bytef*)in;

		do {
			strm.avail_out = CHUNK;
			memset(out, 0, sizeof(out));
			strm.next_out = (Bytef*)out;
			ret = inflate(&strm, Z_NO_FLUSH);
			assert(ret != Z_STREAM_ERROR);
			switch (ret) {
			case Z_NEED_DICT:
				ret = Z_DATA_ERROR;
			case Z_DATA_ERROR:
			case Z_MEM_ERROR:
				(void)inflateEnd(&strm);
				return ret;
			}
			have = CHUNK - strm.avail_out;
			out_offset += have;
		} while (strm.avail_out == 0);
	} while (ret != Z_STREAM_END);

	(void)inflateEnd(&strm);
	ret = Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
	*dst_buf_len = out_offset;

	// begin decompress
	in_offset = out_offset = 0;  

	*dst_buf = malloc(sizeof(char) * (*dst_buf_len));
	memset(*dst_buf, 0, *dst_buf_len);
	ret = inflateInit2(&strm, 47);  
	if(ret != Z_OK) {
		printf("inflateInit2 error:%d",ret);  
		return ret;  
	}

	do {
		copy_len = CHUNK < (src_buf_len - in_offset) ? CHUNK : src_buf_len - in_offset;
		strm.avail_in = copy_len;
		if (strm.avail_in == 0)
			break;

		memset(in, 0, sizeof(in));
		memcpy(in, src_buf + in_offset, copy_len);
		in_offset += copy_len;
		strm.next_in = (Bytef*)in;

		do {
			strm.avail_out = CHUNK;
			memset(out, 0, sizeof(out));
			strm.next_out = (Bytef*)out;
			ret = inflate(&strm, Z_NO_FLUSH);
			assert(ret != Z_STREAM_ERROR);
			switch (ret) {
			case Z_NEED_DICT:
				ret = Z_DATA_ERROR;
			case Z_DATA_ERROR:
			case Z_MEM_ERROR:
				(void)inflateEnd(&strm);
				return ret;
			}
			have = CHUNK - strm.avail_out;
			memcpy((*dst_buf)+out_offset, out, have);
			out_offset += have;
		} while (strm.avail_out == 0);
	} while (ret != Z_STREAM_END);

	(void)inflateEnd(&strm);
	//memset((*dst_buf)+out_offset, 0, 1);
	ret = Z_STREAM_END ? Z_OK : Z_DATA_ERROR;

	return ret;
}

int gz_uncompress_chunk_data(char ** dst_buf, unsigned int * dst_buf_len, char * src_buf, unsigned int src_buf_len)
{	  
	char *p = NULL;
	char *p2 = NULL;
	int inflate_ret=0, have=0;
	int in_offset=0, out_offset=0;
	int chunk_len = 0;
	char chunk_len_buf[10] = {0};
	int copy_len = 0;
	char *magic_header = "\x1f\x8b";
	unsigned int in[CHUNK]={0}, out[CHUNK]={0};  
	z_stream strm;

	strm.zalloc   = Z_NULL;  
	strm.zfree    = Z_NULL;  
	strm.opaque   = Z_NULL; 
	strm.avail_in = 0;
	strm.next_in  = Z_NULL;

	inflate_ret = inflateInit2(&strm, 47);  
	if(inflate_ret != Z_OK) {
		printf("inflateInit2 error:%d",inflate_ret);  
		return inflate_ret;  
	}

	p = src_buf;
	out_offset = 0;

	while (1) {
		if (strncmp(p, "\r\n", strlen("\r\n")) == 0)
			p += strlen("\r\n");
		p2 = strstr(p, "\r\n");
		if (p2 == NULL) {
			return -100;
		}
		memset(chunk_len_buf, 0, sizeof(chunk_len_buf));
		if (sizeof(chunk_len_buf) < p2 - p)
			memcpy(chunk_len_buf, p, sizeof(chunk_len_buf));
		else
			memcpy(chunk_len_buf, p, p2-p);
		chunk_len = strtol(chunk_len_buf, NULL, 16);
		if (chunk_len == 0) break;

		p = p2 + strlen("\r\n");
		if (magic_header != NULL && out_offset == 0) {
			// first chunk			
			if (0 != strncmp(p, magic_header, strlen(magic_header))) {
				return -200;
			}
		}

		in_offset = 0;
		do {
			copy_len = CHUNK < chunk_len-in_offset ? CHUNK : chunk_len-in_offset;
			strm.avail_in = copy_len;
			if (strm.avail_in == 0)
				break;

			memset(in, 0, sizeof(in));
			memcpy(in, p+in_offset, copy_len);
			in_offset += copy_len;
			strm.next_in = (Bytef*)in;

			do {
				strm.avail_out = CHUNK;
				memset(out, 0, sizeof(out));
				strm.next_out = (Bytef*)out;
				inflate_ret = inflate(&strm, Z_NO_FLUSH);
				assert(inflate_ret != Z_STREAM_ERROR);
				switch(inflate_ret) {
				case Z_NEED_DICT:
					inflate_ret = Z_DATA_ERROR;
				case Z_DATA_ERROR:
				case Z_MEM_ERROR:
					(void)inflateEnd(&strm);
					printf("inflate error, with reason=%d\n", inflate_ret);
					return -300;
				}
				have = CHUNK - strm.avail_out;
				memcpy((*dst_buf)+out_offset, out, have);
				out_offset += have;
			} while (strm.avail_out == 0);
		} while (inflate_ret != Z_STREAM_END);

		p += chunk_len;
	}

	(void)inflateEnd(&strm);
	inflate_ret = (inflate_ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR);
	if (inflate_ret != 0) {
		printf("inflate error, with reason = %d\n", inflate_ret);
		return -400;
	}

	*dst_buf_len = out_offset;
	return inflate_ret;
}

void gz_free(void * v)
{
    free(v);
}
