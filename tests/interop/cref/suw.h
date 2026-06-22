/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

Implementation by Ronny Van Keer, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#ifndef XKCP_UTIL_SHAKEUPWRAP_SUW_H
#define XKCP_UTIL_SHAKEUPWRAP_SUW_H

#include "config.h"

#ifdef XKCP_has_ShakingUpAE

#include <stdio.h>
#include <stdint.h>

/*
 * The parallel build encrypts/decrypts independent chunks concurrently, so a
 * smaller chunk gives more units of work and better core utilisation on
 * moderate-sized files. Each chunk is wrapped from a freshly cloned keyed
 * state (see suw.c), with the chunk index and final flag bound in the AAD.
 */
#define SUW_CHUNK_SIZE (4ULL * 1024ULL * 1024ULL)

/* Upper bound on worker threads; the actual count tracks the online CPUs. */
#define SUW_MAX_THREADS 64U

#define SUW_KEY_SIZE   64U
#define SUW_CAPACITY   512U
#define SUW_TAGLEN     (SUW_CAPACITY / 8U)
#define SUW_RHO        ((1600U - SUW_CAPACITY - 64U) / 8U)

/*
 * Each file carries a fresh random salt in a small header. The salt is bound
 * into every chunk's AAD, so the per-chunk nonce is (salt, index, final)
 * rather than just (index, final). This makes chunk nonces unique across files
 * even if the same key were ever reused, and prevents moving an authenticated
 * chunk from one file into another (cross-file splicing).
 */
#define SUW_SALT_SIZE   32U

#define SUW_AAD_SIZE    48U
#define SUW_FINAL_FALSE 0U
#define SUW_FINAL_TRUE  1U

typedef enum {
    SUW_OK = 0,

    /* CLI / argument errors */
    SUW_ERR_INVALID_ARGUMENT,
    SUW_ERR_MISSING_MODE,
    SUW_ERR_MULTIPLE_MODES,
    SUW_ERR_MISSING_KEY_PATH,
    SUW_ERR_UNEXPECTED_POSITIONAL_ARGUMENT,

    /* Key file errors */
    SUW_ERR_KEY_ALREADY_EXISTS,
    SUW_ERR_KEY_NOT_FOUND,
    SUW_ERR_KEY_OPEN_FAILED,
    SUW_ERR_KEY_READ_FAILED,
    SUW_ERR_KEY_WRITE_FAILED,
    SUW_ERR_KEY_INVALID_SIZE,

    /* Input / output errors */
    SUW_ERR_INPUT_READ_FAILED,
    SUW_ERR_OUTPUT_OPEN_FAILED,
    SUW_ERR_OUTPUT_ALREADY_EXISTS,
    SUW_ERR_OUTPUT_WRITE_FAILED,
    SUW_ERR_OUTPUT_CLOSE_FAILED,
    SUW_ERR_OUTPUT_RENAME_FAILED,

    /* Memory / entropy */
    SUW_ERR_MEMORY_ALLOCATION_FAILED,
    SUW_ERR_ENTROPY_FAILED,

    /* Cryptographic / format errors */
    SUW_ERR_INVALID_CIPHERTEXT,
    SUW_ERR_AUTHENTICATION_FAILED,
    SUW_ERR_UNEXPECTED_EOF,

    /* Internal fallback */
    SUW_ERR_INTERNAL
} suw_result_t;

const char *suw_result_message(suw_result_t result);

suw_result_t encrypt_stream(FILE *input, const char *output_path, const char *key_path);
suw_result_t decrypt_stream(FILE *input, const char *output_path, const char *key_path);

#endif /* XKCP_has_ShakingUpAE */

#endif /* XKCP_UTIL_SHAKEUPWRAP_SUW_H */
