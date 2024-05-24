#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

int gzip_compress(const char *input, size_t input_size, unsigned char **output, size_t *output_size) {
    z_stream strm;
    int ret;
    unsigned char out_buffer[8192];

    // Allocate the output buffer
    *output = NULL;
    *output_size = 0;

    // Initialize zlib stream
    memset(&strm, 0, sizeof(strm));
    ret = deflateInit2(&strm, Z_BEST_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK) {
        return ret;
    }

    // Set input data
    strm.next_in = (unsigned char *)input;
    strm.avail_in = input_size;

    do {
        strm.next_out = out_buffer;
        strm.avail_out = sizeof(out_buffer);

        ret = deflate(&strm, Z_FINISH);
        if (ret != Z_STREAM_END && ret != Z_OK && ret != Z_BUF_ERROR) {
            deflateEnd(&strm);
            return ret;
        }

        // Calculate the size of the compressed data
        size_t have = sizeof(out_buffer) - strm.avail_out;
        *output = realloc(*output, *output_size + have);
        if (*output == NULL) {
            deflateEnd(&strm);
            return Z_MEM_ERROR;
        }

        // Copy the compressed data to the output buffer
        memcpy(*output + *output_size, out_buffer, have);
        *output_size += have;
    } while (strm.avail_out == 0);

    deflateEnd(&strm);
    return Z_OK;
}

int gzip_decompress(const unsigned char *input, size_t input_size, char **output, size_t *output_size) {
    z_stream strm;
    int ret;
    unsigned char out_buffer[8192];

    // Allocate the output buffer
    *output = NULL;
    *output_size = 0;

    // Initialize zlib stream
    memset(&strm, 0, sizeof(strm));
    ret = inflateInit2(&strm, 15 + 16);
    if (ret != Z_OK) {
        return ret;
    }

    // Set input data
    strm.next_in = (unsigned char *)input;
    strm.avail_in = input_size;

    do {
        strm.next_out = out_buffer;
        strm.avail_out = sizeof(out_buffer);

        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret != Z_STREAM_END && ret != Z_OK && ret != Z_BUF_ERROR) {
            inflateEnd(&strm);
            return ret;
        }

        // Calculate the size of the decompressed data
        size_t have = sizeof(out_buffer) - strm.avail_out;
        *output = realloc(*output, *output_size + have);
        if (*output == NULL) {
            inflateEnd(&strm);
            return Z_MEM_ERROR;
        }

        // Copy the decompressed data to the output buffer
        memcpy(*output + *output_size, out_buffer, have);
        *output_size += have;
    } while (strm.avail_out == 0);

    inflateEnd(&strm);
    return Z_OK;
}


int main() {
    const char *input = "Hello, world! zlib.";
    size_t input_size = strlen(input);
    unsigned char *compressed_output = NULL;
    size_t compressed_size = 0;
    char *decompressed_output = NULL;
    size_t decompressed_size = 0;

    // Compress the input
    int ret = gzip_compress(input, input_size, &compressed_output, &compressed_size);
    if (ret != Z_OK) {
        fprintf(stderr, "GZIP compression failed: %d\n", ret);
        return 1;
    }

    printf("Input size: %zu bytes\n", input_size);
    printf("Compressed size: %zu bytes\n", compressed_size);

    // Optionally print the compressed data as a hex string
    for (size_t i = 0; i < compressed_size; i++) {
        printf("%02x", compressed_output[i]);
    }
    printf("\n");

    // Decompress the output
    ret = gzip_decompress(compressed_output, compressed_size, &decompressed_output, &decompressed_size);
    if (ret != Z_OK) {
        fprintf(stderr, "GZIP decompression failed: %d\n", ret);
        free(compressed_output);
        return 1;
    }

    printf("Decompressed size: %zu bytes\n", decompressed_size);
    printf("Decompressed output: %s\n", decompressed_output);

    // Free the allocated buffers
    free(compressed_output);
    free(decompressed_output);

    return 0;
}

