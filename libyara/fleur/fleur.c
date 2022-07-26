#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "fnv.h"
#include "fleur.h"

// fleur_bloom_filter_to_file serializes a bloom filter to a file
// it receives a file descriptor
void fleur_bloom_filter_to_file(BloomFilter * bf, FILE* of){
    bf->version = (uint64_t) 1;
    fwrite(&bf->version, sizeof(uint64_t), 1, of);
    fwrite(&bf->h.n, sizeof(uint64_t), 1, of);
    fwrite(&bf->h.p, sizeof(double), 1, of);
    fwrite(&bf->h.k, sizeof(uint64_t), 1, of);
    fwrite(&bf->h.m, sizeof(uint64_t), 1, of);
    fwrite(&bf->h.N, sizeof(uint64_t), 1, of);
    fwrite(bf->v, bf->M * sizeof(uint64_t), 1, of);
    fwrite(bf->Data, bf->datasize * sizeof(unsigned char), 1, of);
}

// fleur_set_data sets the data field of the bloom filter
void fleur_set_data(BloomFilter * bf, char* buf, size_t buf_size ){
    free(bf->Data);
    bf->Data = calloc(buf_size, sizeof(unsigned char));
    bf->datasize = buf_size;
    memcpy(bf->Data, buf, buf_size);
}

// fleur_bloom_filter_from_file returns a pointer to a BloomFilter from a 
// file descriptor.
struct BloomFilter fleur_bloom_filter_from_file(FILE* f){
    BloomFilter bf;
    header h;

    size_t elements_read = fread(&h, sizeof(header), 1, f);
    if(elements_read == 0){
        fprintf(stderr, "Error reading filter file.\n");
        bf.error = 1;
        fclose(f);
        return bf;
    }

    if (fleur_check_header(&h) != 1){
        fprintf(stderr, "Incoherent header.\n");
        bf.error = 1;
        fclose(f);
        return bf;
    }

    bf.M = ceil(h.m / 64.0);

    // Get data size
    int err = fseek(f, 0, SEEK_END);
    if(err!=0){
        fprintf(stderr, "Cannot seek in binary file.\n");
        bf.error = 1;
        fclose(f);
        return bf;
    }
    long size = ftell(f);
    fseek(f, 48, SEEK_SET);

    if (bf.M <= (size - 48)){

        bf.datasize = size - ceil((bf.M*64)/8) - 48;
        
        // Load bitarray
        bf.v = calloc(bf.M, sizeof(uint64_t));
        elements_read = fread(bf.v, sizeof(uint64_t), bf.M, f);
        if(elements_read == 0){
            fprintf(stderr, "Cannot load bitarray.\n");
            bf.error = 1;
            fclose(f);
            return bf;
        }

        // Load remaining data
        if (bf.datasize > 0) {
            // keep one for adding the nullbyte
            bf.Data = calloc(bf.datasize + 1, sizeof(unsigned char));
            elements_read = fread(bf.Data, sizeof(char), bf.datasize, f);
            if(elements_read == 0){
                fprintf(stderr, "Cannot load bloom filter metadata.\n");
                bf.error = 1;
                fclose(f);
                return bf;
            }
            bf.Data[bf.datasize] = '\0';
        }
    }

    bf.modified = 0;
    bf.error = 0;

    bf.h = h;

    return bf;
}

// fleur_fingerprint returns the fingerprint of a given value, as an array of index
// values.
void fleur_fingerprint(BloomFilter * bf, char *buf, size_t buf_size,  uint64_t **fingerprint) {
    uint64_t* tmp = calloc(bf->h.k, sizeof(uint64_t));
    uint64_t h = fnv1(buf, buf_size);
    uint64_t hn = h % m;
    for (uint64_t i = 0; i < bf->h.k; i++){
        hn = (hn * g) % m;
        tmp[i] = (uint64_t)hn % bf->h.m;
    }

    free(*fingerprint);
    *fingerprint = tmp;
}

// fleur_add adds a byte array element to the Bloom filter.
// return 0 when the value is likely already present in the filter
// and -1 when the filter is full 
int fleur_add(BloomFilter * bf, char *buf, size_t buf_size) {
    if ((bf->h.N+1) <= bf->h.n){
        uint64_t k, l;
        int newValue = 0; 
        uint64_t* fp = calloc(bf->h.k, sizeof(uint64_t));
        fleur_fingerprint(bf, buf, buf_size, &fp);
        for (uint64_t i = 0; i < bf->h.k; i++) {
            k = fp[i] / 64;
            l = fp[i] % 64;
            uint64_t v = (uint64_t)1 << l;
            if ((bf->v[k] & v) == 0) {
                newValue = 1;
            }
            bf->v[k] |= v;
        }
        if (newValue == 1) {
            bf->h.N++;
            bf->modified = 1;
            free(fp);
            return 1;
        }else{
            free(fp);
            return 0;
        }
    }else{
        return -1;
    }
}

// fleur_check returns 1 if the given value may be in the Bloom filter, 0 if it
// is definitely not in it.
int fleur_check(BloomFilter * bf, char *buf, size_t buf_size) {
    uint64_t k, l;
    uint64_t* fp = calloc(bf->h.k, sizeof(uint64_t));
    fleur_fingerprint(bf, buf, buf_size, &fp);
    for (uint64_t i = 0; i < bf->h.k; i++){
        k = fp[i] / 64;
        l = fp[i] % 64;
        uint64_t v = (uint64_t)1 << l;
        if ((bf->v[k] & v) == 0){
            free(fp);
            return 0;
        }
    }
    free(fp);
    return 1;
}

// fleur_initialize creates a an empty Bloom filter with the given capacity (n)
// and FP probability (p).
struct BloomFilter fleur_initialize(uint64_t n, double p, char *buf){
    BloomFilter bf;

    uint64_t m = fabs(ceil((double)(n) * log(p) / pow(log(2.0), 2.0)));
    uint64_t k = ceil(log(2) * m / n );

	bf.Data = (unsigned char*)buf; 

    bf.M = ceil(m / 64.0);

    bf.v = calloc(bf.M, sizeof(uint64_t));

    header h = {1, n, p, k, m, 0};

    bf.h = h;

    bf.modified = 0;
    return bf;
}

// fleur_print_header prints a BloomFilter's header
void fleur_print_header(header * h){
    printf("Header details:\n version: %lu\n n: %lu \n p: %f\n k: %lu \n m: %lu \n N: %lu \n",
        h->version,
        h->n,
        h->p,
        h->k,
        h->m,
        h->N);
}

// fleur_check_printer check a BloomFilter's header for inconsistencies
int fleur_check_header(header * h){
    if (h->version != 1){
        fprintf(stderr, "Current filter version not supported.\n");
        return 0;
    }
    // 0111111111111111111111111111111111111111111111111111111111111111b
    uint64_t maxint = 9223372036854775807;
    if (h->k >= maxint){
        fprintf(stderr, "value of k (number of hash functions) is too high.\n");
        return 0;
    }
    if (h->p <= __DBL_EPSILON__){
        fprintf(stderr, "p is too small.\n");
        return 0;
    }
    if (h->p > 1){
        fprintf(stderr, "p is more than one.\n");
        return 0;
    }
    if (h->N > h->n){
        fprintf(stderr, "incoherent filter.\n");
        return 0;
    }
    uint64_t tmp_m = fabs(ceil((double)(h->n) * log(h->p) / pow(log(2.0), 2.0)));
    if (tmp_m != h->m){
        fprintf(stderr, "incoherent filter.\n");
        return 0;
    }
    uint64_t tmp_k = ceil(log(2) * h->m / h->n );
    if (tmp_k != h->k){
        fprintf(stderr, "incoherent filter values.\n");
        return 0;
    }
    return 1;
}

// fleur_printer_filter prints a BloomFilter's details
void fleur_print_filter(BloomFilter * bf){
    printf("Filter details:\n n: %lu \n p: %f\n k: %lu \n m: %lu \n N: %lu \n M: %lu\n Data: %s.",
    bf->h.n,
    bf->h.p,
    bf->h.k,
    bf->h.m,
    bf->h.N,
    bf->M,
    bf->Data);
}