// Group: 21
// Authors: Alex Nelson, Jose Contreras-Perez, Julio Chavez, Wyatt Jones
// NetIDs: alexn1@usf.edu | josec40@usf.edu | julioc10@usf.edu | wyattj1@usf.edu
// Description: Cracks a list of hashes in parallel while preserving the first matching password from the input file.


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>

#include "hash_functions.h"


#define KEEP 16 // only the first 16 bytes of a hash are kept
#define N_ALGS 4
#define MAX_WORKERS 10


struct cracked_hash {
    unsigned char hash[KEEP];
    char *password, *alg;
};

typedef unsigned char * (*hashing)(unsigned char *, unsigned int);

hashing fn[N_ALGS] = {calculate_md5, calculate_sha1, calculate_sha256, calculate_sha512};
char *algs[N_ALGS] = {"MD5", "SHA1", "SHA256", "SHA512"};

struct worker_args {
    char **passwords;
    size_t start;
    size_t end;
    struct cracked_hash *cracked_hashes;
    int n_hashed;
    size_t *match_indices;
    int *match_algs;
    int *bucket_heads;
    int *next_target;
};


// Compare two hashes stored as raw bytes.
int compare_hashes(unsigned char *a, unsigned char *b) {
    for(int i=0; i < KEEP; i++)
        if(a[i] != b[i])
            return 0;
    return 1;
}


// Convert one hexadecimal character to its numeric value.
unsigned char hex_value(char digit) {
    if (digit >= '0' && digit <= '9')
        return (unsigned char)(digit - '0');

    if (digit >= 'a' && digit <= 'f')
        return (unsigned char)(digit - 'a' + 10);
    
    return (unsigned char)(digit - 'A' + 10);
}


// Decode a 32-character hexadecimal hash into 16 raw bytes.
void decode_hash(char *hex_hash, unsigned char *hash) {
    for (int i = 0; i < KEEP; i++) {
        hash[i] = (unsigned char)((hex_value(hex_hash[2*i]) << 4) | hex_value(hex_hash[2*i+1]));
    }
}


// Reads the password file once and splits it in place.
// This avoids synchronized file access and gives every worker a contiguous range to process.
char **load_passwords(const char *filename, char **file_data, size_t *n_passwords) {
    // Open the file and determine how much memory is needed for its contents
    FILE *fp = fopen(filename, "rb");
    assert(fp != NULL);
    int status = fseek(fp, 0, SEEK_END);
    assert(status == 0);
    long file_size = ftell(fp);
    assert(file_size >= 0);
    rewind(fp);

    // Read the passwords file into one buffer that's shared by all worker threads
    char *data = malloc((size_t)file_size + 1);
    assert(data != NULL);
    size_t bytes_read = fread(data, 1, (size_t)file_size, fp);
    assert(bytes_read == (size_t)file_size);
    fclose(fp);
    data[bytes_read] = '\0';

    // Count the passwords that are separated by whitespace before allocating the pointer list
    size_t count = 0;
    int in_password = 0;
    for (size_t i = 0; i < bytes_read; i++) {
        if (data[i] == '\n') {
            in_password = 0;
        }
        else if (!in_password) {
            count++;
            in_password = 1;
        }
    }

    char **passwords = NULL;
    if (count != 0) {
        passwords = malloc(count * sizeof(*passwords));
        assert(passwords != NULL);
    }

    // Replace separators with null terminators and point to each password in data
    size_t next = 0;
    char *cursor = data;
    char *end = data + bytes_read;
    while (cursor < end) {
        while (cursor < end && *cursor == '\n') {
            *cursor++ = '\0';
        }

        if (cursor == end)
            break;

        passwords[next++] = cursor;
        while (cursor < end && *cursor != '\n') {
            cursor++;
        }
    }

    // Return both the pointer list and its backing buffer to the caller
    *file_data = data;
    *n_passwords = count;
    return passwords;
}


// Each worker records only its own first match for every target.
// Therefore no locks are needed in the loop and thread scheduling can't alter which password is selected
void *crack_range(void *argument) {
    // Recover this thread's password range and result arrays
    struct worker_args *args = argument;

    // Process the worker's contiguous portion of the password list in order
    for (size_t password_index = args->start; password_index < args->end; password_index++) {
        char *password = args->passwords[password_index];
        unsigned int length = (unsigned int)strlen(password);

        // Compute each supported hash as raw bytes
        for (int alg = 0; alg < N_ALGS; alg++) {
            // Call the current hash function using the password and its length
            unsigned char *hash = fn[alg]((unsigned char *)password, length);
            assert(hash != NULL);

            // Only inspect targets whose first byte matches the computed hash
            int target = args->bucket_heads[hash[0]];
            while (target != -1) {
                // Skip targets that this worker already matched earlier
                if (args->match_indices[target] == (size_t)-1 &&
                    compare_hashes(hash, args->cracked_hashes[target].hash)) {
                    // Save both the password position and algorithm used
                    args->match_indices[target] = password_index;
                    args->match_algs[target] = alg;
                }

                // Move to the next target in this bucket
                target = args->next_target[target];
            }

            // The hash functions allocate a new digest for every calculation
            free(hash);
        }
    }
    return NULL;
}


// Compute hashes in parallel and print matches in the original target order.
void crack_hashed_passwords(char *password_list, char *hashed_list, char *output) {
    FILE *fp;
    char hex_hash[2*KEEP+1]; // hashed passwords have at most 'keep' characters

    // Load and count the hexadecimal target hashes
    int n_hashed = 0;
    struct cracked_hash *cracked_hashes;
    fp = fopen(hashed_list, "r");
    assert(fp != NULL);
    while(fscanf(fp, "%32s", hex_hash) == 1)
        n_hashed++;
    rewind(fp);
    cracked_hashes = (struct cracked_hash *) malloc(n_hashed*sizeof(struct cracked_hash));
    assert(cracked_hashes != NULL);

    // Decode each target once so workers can compare raw bytes directly
    for(int i=0; i < n_hashed; i++) {
        fscanf(fp, "%32s", hex_hash);
        decode_hash(hex_hash, cracked_hashes[i].hash);
        cracked_hashes[i].password = NULL;
        cracked_hashes[i].alg = NULL;
    }
    fclose(fp);

    // Group target indices by their first byte to avoid checking every target
    int bucket_heads[256];
    int *next_target = NULL;
    for (int i = 0; i < 256; i++) {
        bucket_heads[i] = -1;
    }
    if (n_hashed != 0) {
        next_target = malloc((size_t)n_hashed * sizeof(*next_target));
        assert(next_target != NULL);
        for (int target = 0; target < n_hashed; target++) {
            unsigned int bucket = cracked_hashes[target].hash[0];
            next_target[target] = bucket_heads[bucket];
            bucket_heads[bucket] = target;
        }
    }

    // Load passwords before starting workers so they can read disjoint ranges
    char *password_data;
    size_t n_passwords;
    char **passwords = load_passwords(password_list, &password_data, &n_passwords);
    int worker_count = n_passwords < MAX_WORKERS ? (int)n_passwords : MAX_WORKERS;

    // Store thread handles, arguments, and one private result set per worker
    pthread_t workers[MAX_WORKERS];
    struct worker_args args[MAX_WORKERS];
    size_t *all_indices = NULL;
    int *all_algs = NULL;
    if (worker_count != 0 && n_hashed != 0) {
        // An index marks targets that a worker did not find
        size_t result_count = (size_t)worker_count * (size_t)n_hashed;
        all_indices = malloc(result_count * sizeof(*all_indices));
        all_algs = malloc(result_count * sizeof(*all_algs));
        assert(all_indices != NULL && all_algs != NULL);
        for (size_t i = 0; i < result_count; i++) {
            all_indices[i] = (size_t)-1;
        }

        // Divide the ordered password list evenly and launch each worker
        for (int i = 0; i < worker_count; i++) {
            args[i].passwords = passwords;
            args[i].start = n_passwords * (size_t)i / (size_t)worker_count;
            args[i].end = n_passwords * (size_t)(i + 1) / (size_t)worker_count;
            args[i].cracked_hashes = cracked_hashes;
            args[i].n_hashed = n_hashed;
            args[i].match_indices = all_indices + (size_t)i * n_hashed;
            args[i].match_algs = all_algs + (size_t)i * n_hashed;
            args[i].bucket_heads = bucket_heads;
            args[i].next_target = next_target;
            int status = pthread_create(&workers[i], NULL, crack_range, &args[i]);
            assert(status == 0);
        }

        // Wait until every worker has finished before combining its results
        for (int i = 0; i < worker_count; i++) {
            int status = pthread_join(workers[i], NULL);
            assert(status == 0);
        }

        // Select the globally earliest match, preserving sequential behavior
        for (int target = 0; target < n_hashed; target++) {
            // Begin with a index indicating that no worker found this target
            size_t best_index = (size_t)-1;
            int best_alg = 0;

            // Check this target's private result from every worker.
            for (int worker = 0; worker < worker_count; worker++) {
                // Locate the target within the worker's section of the result arrays
                size_t offset = (size_t)worker * n_hashed + target;

                // A smaller index means the password appeared earlier in the file
                if (all_indices[offset] < best_index) {
                    best_index = all_indices[offset];
                    best_alg = all_algs[offset];
                }
            }

            // Store the earliest match and its algorithm in the final result
            if (best_index != (size_t)-1) {
                cracked_hashes[target].password = passwords[best_index];
                cracked_hashes[target].alg = algs[best_alg];
            }
        }
    }

    // print results
    fp = fopen(output, "w");
    assert(fp != NULL);
    for(int i=0; i < n_hashed; i++) {
        if(cracked_hashes[i].password ==  NULL)
            fprintf(fp, "not found\n");
        else
            fprintf(fp, "%s:%s\n", cracked_hashes[i].password, cracked_hashes[i].alg);
    }
    fclose(fp);

    free(all_algs);
    free(all_indices);
    free(next_target);
    free(passwords);
    free(password_data);
    free(cracked_hashes);
}

