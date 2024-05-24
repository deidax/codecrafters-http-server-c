#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

int compressToGzip(const char *input, int inputSize, char *output, int outputSize);
int uncompressFromGzip(const char *input, int inputSize, char *output, int outputSize);

int main() {
    const char *input = "Hello World TEST";
    int inputSize = strlen(input) + 1;  // Include null terminator

    // Allocate memory for the compressed data
    int compressedSize = inputSize * 2;  // Assume compressed size won't exceed 2 times the input size
    char *compressedData = (char *)malloc(compressedSize);
    if (compressedData == NULL) {
        fprintf(stderr, "Error allocating memory for compressed data.\n");
        return 1;
    }

    // Compress the input string
    int compressedDataSize = compressToGzip(input, inputSize, compressedData, compressedSize);
    if (compressedDataSize < 0) {
        fprintf(stderr, "Error compressing data.\n");
        free(compressedData);
        return 1;
    }

    // Print the compressed data as hexadecimal
    printf("Compressed data (hexadecimal representation): ");
    for (int i = 0; i < compressedDataSize; i++) {
        printf("%02x", (unsigned char)compressedData[i]);
    }
    printf("\nCompressed size: %d\n", compressedDataSize);

    // Allocate memory for the decompressed data
    char *decompressedData = (char *)malloc(inputSize);
    if (decompressedData == NULL) {
        fprintf(stderr, "Error allocating memory for decompressed data.\n");
        free(compressedData);
        return 1;
    }

    // Decompress the compressed data
    int decompressedDataSize = uncompressFromGzip(compressedData, compressedDataSize, decompressedData, inputSize);
    if (decompressedDataSize < 0) {
        fprintf(stderr, "Error decompressing data.\n");
        free(compressedData);
        free(decompressedData);
        return 1;
    }

    // Print the decompressed data
    printf("Decompressed data: %s\n", decompressedData);

    // Clean up
    free(compressedData);
    free(decompressedData);

    return 0;
}

int compressToGzip(const char *input, int inputSize, char *output, int outputSize) {
    z_stream zs = {0};
    zs.zalloc = Z_NULL;
    zs.zfree = Z_NULL;
    zs.opaque = Z_NULL;
    zs.avail_in = (uInt)inputSize;
    zs.next_in = (Bytef *)input;
    zs.avail_out = (uInt)outputSize;
    zs.next_out = (Bytef *)output;

    deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 | 16, 8, Z_DEFAULT_STRATEGY);
    deflate(&zs, Z_FINISH);
    deflateEnd(&zs);

    return zs.total_out;
}

int uncompressFromGzip(const char *input, int inputSize, char *output, int outputSize) {
    z_stream zs = {0};
    zs.zalloc = Z_NULL;
    zs.zfree = Z_NULL;
    zs.opaque = Z_NULL;
    zs.avail_in = (uInt)inputSize;
    zs.next_in = (Bytef *)input;
    zs.avail_out = (uInt)outputSize;
    zs.next_out = (Bytef *)output;

    inflateInit2(&zs, 16 + MAX_WBITS); // Add 16 to windowBits to enable gzip decoding
    inflate(&zs, Z_FINISH);
    inflateEnd(&zs);

    return zs.total_out;
}
