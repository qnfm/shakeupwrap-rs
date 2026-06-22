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

#include "config.h"

#ifdef XKCP_has_ShakingUpAE

#include "suw.h"
#include "ShakingUpAE.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

typedef struct {
    FILE *fp;
    char *tmp_path;
    const char *final_path;
    int should_close;
    int committed;
} suw_output_t;

const char *suw_result_message(suw_result_t result)
{
    switch (result) {
    case SUW_OK:
        return "Success";

    case SUW_ERR_INVALID_ARGUMENT:
        return "Invalid argument";
    case SUW_ERR_MISSING_MODE:
        return "Missing required mode: specify -e or -d";
    case SUW_ERR_MULTIPLE_MODES:
        return "Invalid mode: specify exactly one of -e or -d";
    case SUW_ERR_MISSING_KEY_PATH:
        return "Missing required key path: -k KEYFILE";
    case SUW_ERR_UNEXPECTED_POSITIONAL_ARGUMENT:
        return "Unexpected positional argument";

    case SUW_ERR_KEY_ALREADY_EXISTS:
        return "Key file already exists";
    case SUW_ERR_KEY_NOT_FOUND:
        return "Key file does not exist";
    case SUW_ERR_KEY_OPEN_FAILED:
        return "Failed to open key file";
    case SUW_ERR_KEY_READ_FAILED:
        return "Failed to read key file";
    case SUW_ERR_KEY_WRITE_FAILED:
        return "Failed to write key file";
    case SUW_ERR_KEY_INVALID_SIZE:
        return "Invalid key file size";

    case SUW_ERR_INPUT_READ_FAILED:
        return "Failed to read input";
    case SUW_ERR_OUTPUT_OPEN_FAILED:
        return "Failed to open output file";
    case SUW_ERR_OUTPUT_ALREADY_EXISTS:
        return "Output file already exists";
    case SUW_ERR_OUTPUT_WRITE_FAILED:
        return "Failed to write output";
    case SUW_ERR_OUTPUT_CLOSE_FAILED:
        return "Failed to close output file";
    case SUW_ERR_OUTPUT_RENAME_FAILED:
        return "Failed to rename temporary output file";

    case SUW_ERR_MEMORY_ALLOCATION_FAILED:
        return "Memory allocation failed";
    case SUW_ERR_ENTROPY_FAILED:
        return "Failed to generate key material";

    case SUW_ERR_INVALID_CIPHERTEXT:
        return "Invalid ciphertext";
    case SUW_ERR_AUTHENTICATION_FAILED:
        return "Authentication failed";
    case SUW_ERR_UNEXPECTED_EOF:
        return "Unexpected end of input";

    case SUW_ERR_INTERNAL:
    default:
        return "Internal error";
    }
}

static void secure_clear(void *ptr, size_t len)
{
    if (ptr == NULL) {
        return;
    }

#if defined(__STDC_LIB_EXT1__)
    (void)memset_s(ptr, len, 0, len);
#else
    volatile unsigned char *p = (volatile unsigned char *)ptr;

    while (len-- != 0) {
        *p++ = 0;
    }
#endif
}

static void store_u64_le(uint8_t out[8], uint64_t x)
{
    out[0] = (uint8_t)(x);
    out[1] = (uint8_t)(x >> 8);
    out[2] = (uint8_t)(x >> 16);
    out[3] = (uint8_t)(x >> 24);
    out[4] = (uint8_t)(x >> 32);
    out[5] = (uint8_t)(x >> 40);
    out[6] = (uint8_t)(x >> 48);
    out[7] = (uint8_t)(x >> 56);
}

static void make_chunk_aad(uint8_t aad[SUW_AAD_SIZE],
                           const uint8_t salt[SUW_SALT_SIZE],
                           uint64_t chunk_index,
                           uint8_t final_flag)
{
    memset(aad, 0, SUW_AAD_SIZE);
    memcpy(aad, salt, SUW_SALT_SIZE);
    store_u64_le(aad + SUW_SALT_SIZE, chunk_index);
    aad[SUW_SALT_SIZE + 8] = final_flag;
}

static suw_result_t write_all_fd(int fd, const uint8_t *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, buf, len);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return SUW_ERR_KEY_WRITE_FAILED;
        }

        if (n == 0) {
            return SUW_ERR_KEY_WRITE_FAILED;
        }

        buf += (size_t)n;
        len -= (size_t)n;
    }

    return SUW_OK;
}

static suw_result_t read_exact_fd(int fd, uint8_t *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = read(fd, buf, len);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return SUW_ERR_KEY_READ_FAILED;
        }

        if (n == 0) {
            return SUW_ERR_KEY_INVALID_SIZE;
        }

        buf += (size_t)n;
        len -= (size_t)n;
    }

    return SUW_OK;
}

static suw_result_t write_all_file(FILE *out, const uint8_t *buf, size_t len)
{
    while (len > 0) {
        size_t written = fwrite(buf, 1, len, out);

        if (written == 0) {
            return SUW_ERR_OUTPUT_WRITE_FAILED;
        }

        buf += written;
        len -= written;
    }

    return SUW_OK;
}

/*
 * Fill a buffer unless EOF is reached.
 *
 * hit_eof is set when fewer than len bytes were read because the stream ended.
 * For regular files and pipes, this prevents accidental short reads from being
 * treated as chunk boundaries.
 */
static suw_result_t read_full_or_eof(FILE *input,
                                     uint8_t *buf,
                                     size_t len,
                                     size_t *bytes_read,
                                     int *hit_eof)
{
    size_t total = 0;

    while (total < len) {
        size_t n = fread(buf + total, 1, len - total, input);

        if (n > 0) {
            total += n;
            continue;
        }

        if (ferror(input)) {
            return SUW_ERR_INPUT_READ_FAILED;
        }

        if (feof(input)) {
            break;
        }
    }

    *bytes_read = total;
    *hit_eof = total < len;

    return SUW_OK;
}

/*
 * Parallel, pipelined chunk processing.
 *
 * ShakingUpAE's DWrap is a stateful duplex, so the original streaming format
 * chains every chunk and is strictly serial. This build makes each chunk an
 * independent message: it is wrapped from a *clone* of the initial keyed
 * instance, with a per-file random salt plus the chunk index and final flag
 * bound in the AAD. Independent chunks are processed by a pipeline that fully
 * overlaps I/O with compute:
 *
 *   reader thread  -> bounded slot ring -> N compute workers -> ordered writer
 *
 * A dedicated reader streams chunks into a ring of slots; a pool of workers
 * encrypts/decrypts whichever slots are ready; the writer (the calling thread)
 * drains finished slots strictly in sequence order. Reads of upcoming chunks,
 * the parallel crypto, and writes of finished chunks therefore all happen at
 * the same time, removing the read/compute/write barrier of a batch design.
 *
 * The AAD still binds ordering and finality (and now the file salt), so
 * truncation, reordering, cross-file splicing and tampering remain detectable.
 */

typedef enum {
    SUW_SLOT_EMPTY = 0,   /* free for the reader to use */
    SUW_SLOT_RESERVED,    /* reader is reading into it */
    SUW_SLOT_FILLED,      /* data ready, queued for a worker */
    SUW_SLOT_COMPUTING,   /* a worker is processing it */
    SUW_SLOT_DONE         /* processed, ready for the writer */
} suw_slot_state_t;

typedef struct {
    uint8_t          *in;
    uint8_t          *out;
    size_t            in_len;
    size_t            out_len;
    uint64_t          seq;
    uint8_t           final_flag;
    int               auth_ok;
    suw_slot_state_t  state;
} suw_slot_t;

typedef struct {
    suw_slot_t *slots;
    size_t      nslots;

    const KeccakWidth1600_DWrapInstance *base;
    const uint8_t *salt;
    int         is_decrypt;

    size_t     *queue;        /* FIFO of FILLED slot indices */
    size_t      qhead;
    size_t      qtail;
    size_t      qcount;

    pthread_mutex_t mtx;
    pthread_cond_t  slot_free;   /* a slot became EMPTY */
    pthread_cond_t  work_avail;  /* queue non-empty OR shutdown */
    pthread_cond_t  slot_done;   /* a slot became DONE */

    int        error;         /* first suw_result_t failure, or SUW_OK */
    int        shutdown;      /* workers should exit once the queue drains */
} suw_pipeline_t;

static unsigned suw_num_threads(void)
{
    long n = sysconf(_SC_NPROCESSORS_ONLN);

    if (n < 1) {
        n = 1;
    }
    if (n > (long)SUW_MAX_THREADS) {
        n = (long)SUW_MAX_THREADS;
    }

    return (unsigned)n;
}

static void suw_slot_process(suw_pipeline_t *p, suw_slot_t *s)
{
    KeccakWidth1600_DWrapInstance local;
    uint8_t aad[SUW_AAD_SIZE];

    SHAKE_Wrap_Clone(&local, p->base);
    make_chunk_aad(aad, p->salt, s->seq, s->final_flag);

    if (p->is_decrypt) {
        if (SHAKE_Wrap_Unwrap(&local, s->out, aad, sizeof(aad),
                              s->in, s->in_len) == 0) {
            s->auth_ok = 1;
            s->out_len = s->in_len - SUW_TAGLEN;
        } else {
            s->auth_ok = 0;
            s->out_len = 0;
        }
    } else {
        SHAKE_Wrap_Wrap(&local, s->out, aad, sizeof(aad), s->in, s->in_len);
        s->auth_ok = 1;
        s->out_len = s->in_len + SUW_TAGLEN;
    }
}

static void *suw_compute_worker(void *arg)
{
    suw_pipeline_t *p = (suw_pipeline_t *)arg;

    for (;;) {
        size_t idx;

        pthread_mutex_lock(&p->mtx);
        while (p->qcount == 0 && !p->shutdown) {
            pthread_cond_wait(&p->work_avail, &p->mtx);
        }
        if (p->qcount == 0 && p->shutdown) {
            pthread_mutex_unlock(&p->mtx);
            break;
        }
        idx = p->queue[p->qhead];
        p->qhead = (p->qhead + 1) % p->nslots;
        p->qcount--;
        p->slots[idx].state = SUW_SLOT_COMPUTING;
        pthread_mutex_unlock(&p->mtx);

        suw_slot_process(p, &p->slots[idx]);

        pthread_mutex_lock(&p->mtx);
        p->slots[idx].state = SUW_SLOT_DONE;
        pthread_cond_broadcast(&p->slot_done);
        pthread_mutex_unlock(&p->mtx);
    }

    return NULL;
}

/* Record the first failure and wake everyone so the pipeline unwinds. */
static void suw_pipeline_fail(suw_pipeline_t *p, suw_result_t err)
{
    pthread_mutex_lock(&p->mtx);
    if (p->error == SUW_OK) {
        p->error = err;
    }
    pthread_cond_broadcast(&p->slot_free);
    pthread_cond_broadcast(&p->work_avail);
    pthread_cond_broadcast(&p->slot_done);
    pthread_mutex_unlock(&p->mtx);
}

/* Reserve the slot for sequence number seq; returns SIZE_MAX on error/abort. */
static size_t suw_reader_acquire(suw_pipeline_t *p, uint64_t seq)
{
    size_t idx = (size_t)(seq % p->nslots);

    pthread_mutex_lock(&p->mtx);
    while (p->slots[idx].state != SUW_SLOT_EMPTY && p->error == SUW_OK) {
        pthread_cond_wait(&p->slot_free, &p->mtx);
    }
    if (p->error != SUW_OK) {
        pthread_mutex_unlock(&p->mtx);
        return SIZE_MAX;
    }
    p->slots[idx].state = SUW_SLOT_RESERVED;
    pthread_mutex_unlock(&p->mtx);

    return idx;
}

static void suw_reader_release(suw_pipeline_t *p, size_t idx)
{
    pthread_mutex_lock(&p->mtx);
    p->slots[idx].state = SUW_SLOT_EMPTY;
    pthread_cond_broadcast(&p->slot_free);
    pthread_mutex_unlock(&p->mtx);
}

static void suw_reader_publish(suw_pipeline_t *p, size_t idx, uint64_t seq,
                               size_t in_len, uint8_t final_flag)
{
    pthread_mutex_lock(&p->mtx);
    p->slots[idx].seq = seq;
    p->slots[idx].in_len = in_len;
    p->slots[idx].final_flag = final_flag;
    p->slots[idx].state = SUW_SLOT_FILLED;
    p->queue[p->qtail] = idx;
    p->qtail = (p->qtail + 1) % p->nslots;
    p->qcount++;
    pthread_cond_signal(&p->work_avail);
    pthread_mutex_unlock(&p->mtx);
}

static suw_result_t suw_validate_dec_chunk(size_t cur_len, uint8_t final_flag,
                                           uint64_t seq)
{
    if (cur_len < SUW_TAGLEN) {
        return SUW_ERR_INVALID_CIPHERTEXT;
    }
    if (final_flag == SUW_FINAL_FALSE && cur_len != SUW_CHUNK_SIZE + SUW_TAGLEN) {
        return SUW_ERR_INVALID_CIPHERTEXT;
    }
    if (final_flag == SUW_FINAL_TRUE && cur_len > SUW_CHUNK_SIZE + SUW_TAGLEN) {
        return SUW_ERR_INVALID_CIPHERTEXT;
    }
    /* An empty final chunk is valid only for empty plaintext. */
    if (final_flag == SUW_FINAL_TRUE && cur_len == SUW_TAGLEN && seq != 0) {
        return SUW_ERR_INVALID_CIPHERTEXT;
    }
    return SUW_OK;
}

typedef struct {
    suw_pipeline_t *p;
    FILE           *input;
    size_t          read_cap;
} suw_reader_arg_t;

static void *suw_reader_main(void *arg)
{
    suw_reader_arg_t *ra = (suw_reader_arg_t *)arg;
    suw_pipeline_t   *p = ra->p;
    FILE             *input = ra->input;
    size_t            cap = ra->read_cap;

    uint64_t     seq = 0;
    size_t       pending_idx;
    size_t       pending_len = 0;
    size_t       len = 0;
    int          eof = 0;
    suw_result_t r;

    pending_idx = suw_reader_acquire(p, 0);
    if (pending_idx == SIZE_MAX) {
        return NULL;
    }

    r = read_full_or_eof(input, p->slots[pending_idx].in, cap, &len, &eof);
    if (r != SUW_OK) {
        suw_pipeline_fail(p, r);
        return NULL;
    }

    if (len == 0 && eof) {
        if (p->is_decrypt) {
            suw_pipeline_fail(p, SUW_ERR_INVALID_CIPHERTEXT);
            return NULL;
        }
        /* Empty plaintext: a single empty final chunk. */
        suw_reader_publish(p, pending_idx, 0, 0, SUW_FINAL_TRUE);
        return NULL;
    }
    pending_len = len;

    for (;;) {
        size_t la_idx;
        size_t next_len = 0;
        int    next_eof = 0;
        uint8_t final_flag;

        la_idx = suw_reader_acquire(p, seq + 1);
        if (la_idx == SIZE_MAX) {
            return NULL;
        }

        r = read_full_or_eof(input, p->slots[la_idx].in, cap, &next_len, &next_eof);
        if (r != SUW_OK) {
            suw_reader_release(p, la_idx);
            suw_pipeline_fail(p, r);
            return NULL;
        }

        final_flag = (next_len == 0 && next_eof) ? SUW_FINAL_TRUE : SUW_FINAL_FALSE;

        if (p->is_decrypt) {
            suw_result_t v = suw_validate_dec_chunk(pending_len, final_flag, seq);
            if (v != SUW_OK) {
                suw_reader_release(p, la_idx);
                suw_pipeline_fail(p, v);
                return NULL;
            }
        }

        suw_reader_publish(p, pending_idx, seq, pending_len, final_flag);

        if (final_flag == SUW_FINAL_TRUE) {
            suw_reader_release(p, la_idx);
            return NULL;
        }

        pending_idx = la_idx;
        pending_len = next_len;
        seq++;
    }
}

static suw_result_t suw_writer_run(suw_pipeline_t *p, suw_output_t *output)
{
    uint64_t     seq = 0;
    suw_result_t result = SUW_OK;

    for (;;) {
        size_t  idx = (size_t)(seq % p->nslots);
        uint8_t final_flag;
        int     auth_ok;
        size_t  out_len;

        pthread_mutex_lock(&p->mtx);
        while (p->slots[idx].state != SUW_SLOT_DONE && p->error == SUW_OK) {
            pthread_cond_wait(&p->slot_done, &p->mtx);
        }
        if (p->slots[idx].state != SUW_SLOT_DONE) {
            result = p->error;
            pthread_mutex_unlock(&p->mtx);
            break;
        }
        final_flag = p->slots[idx].final_flag;
        auth_ok = p->slots[idx].auth_ok;
        out_len = p->slots[idx].out_len;
        pthread_mutex_unlock(&p->mtx);

        if (p->is_decrypt && !auth_ok) {
            result = SUW_ERR_AUTHENTICATION_FAILED;
            break;
        }

        result = write_all_file(output->fp, p->slots[idx].out, out_len);
        if (result != SUW_OK) {
            break;
        }

        pthread_mutex_lock(&p->mtx);
        p->slots[idx].state = SUW_SLOT_EMPTY;
        pthread_cond_broadcast(&p->slot_free);
        pthread_mutex_unlock(&p->mtx);

        if (final_flag == SUW_FINAL_TRUE) {
            break;
        }
        seq++;
    }

    if (result != SUW_OK) {
        suw_pipeline_fail(p, result);
    }

    return result;
}

/*
 * Run the encrypt/decrypt pipeline end to end. base is the initial keyed
 * instance, salt the per-file salt; both are read-only and shared by workers.
 */
static suw_result_t suw_run_pipeline(FILE *input, suw_output_t *output,
                                     const KeccakWidth1600_DWrapInstance *base,
                                     const uint8_t *salt, int is_decrypt)
{
    suw_pipeline_t p;
    unsigned       nthreads = suw_num_threads();
    size_t         nslots = (size_t)nthreads * 2u;
    size_t         in_cap = is_decrypt ? (SUW_CHUNK_SIZE + SUW_TAGLEN) : SUW_CHUNK_SIZE;
    size_t         out_cap = is_decrypt ? SUW_CHUNK_SIZE : (SUW_CHUNK_SIZE + SUW_TAGLEN);
    pthread_t      workers[SUW_MAX_THREADS];
    unsigned       created = 0;
    pthread_t      reader;
    int            reader_started = 0;
    suw_reader_arg_t ra;
    suw_result_t   result = SUW_OK;
    size_t         i;
    int            mutex_ready = 0, c1 = 0, c2 = 0, c3 = 0;

    if (nslots < 3) {
        nslots = 3;
    }

    memset(&p, 0, sizeof(p));
    p.nslots = nslots;
    p.base = base;
    p.salt = salt;
    p.is_decrypt = is_decrypt;
    p.error = SUW_OK;

    p.slots = calloc(nslots, sizeof(*p.slots));
    p.queue = calloc(nslots, sizeof(*p.queue));
    if (p.slots == NULL || p.queue == NULL) {
        result = SUW_ERR_MEMORY_ALLOCATION_FAILED;
        goto cleanup;
    }
    for (i = 0; i < nslots; i++) {
        p.slots[i].in = malloc(in_cap);
        p.slots[i].out = malloc(out_cap);
        if (p.slots[i].in == NULL || p.slots[i].out == NULL) {
            result = SUW_ERR_MEMORY_ALLOCATION_FAILED;
            goto cleanup;
        }
    }

    if (pthread_mutex_init(&p.mtx, NULL) != 0) {
        result = SUW_ERR_INTERNAL;
        goto cleanup;
    }
    mutex_ready = 1;
    if (pthread_cond_init(&p.slot_free, NULL) != 0 ||
        (c1 = 1, pthread_cond_init(&p.work_avail, NULL) != 0) ||
        (c2 = 1, pthread_cond_init(&p.slot_done, NULL) != 0)) {
        result = SUW_ERR_INTERNAL;
        goto cleanup;
    }
    c3 = 1;

    for (i = 0; i < nthreads; i++) {
        if (pthread_create(&workers[created], NULL, suw_compute_worker, &p) == 0) {
            created++;
        }
    }
    if (created == 0) {
        result = SUW_ERR_INTERNAL;
        goto cleanup;
    }

    ra.p = &p;
    ra.input = input;
    ra.read_cap = in_cap;
    if (pthread_create(&reader, NULL, suw_reader_main, &ra) == 0) {
        reader_started = 1;
    } else {
        result = SUW_ERR_INTERNAL;
        suw_pipeline_fail(&p, result);
    }

    if (reader_started) {
        result = suw_writer_run(&p, output);
    }

    /* Shut the workers down and join everything. */
    pthread_mutex_lock(&p.mtx);
    p.shutdown = 1;
    pthread_cond_broadcast(&p.work_avail);
    pthread_cond_broadcast(&p.slot_free);
    pthread_cond_broadcast(&p.slot_done);
    pthread_mutex_unlock(&p.mtx);

    if (reader_started) {
        pthread_join(reader, NULL);
    }
    for (i = 0; i < created; i++) {
        pthread_join(workers[i], NULL);
    }

    if (result == SUW_OK && p.error != SUW_OK) {
        result = p.error;
    }

cleanup:
    if (c3) {
        pthread_cond_destroy(&p.slot_done);
    }
    if (c2) {
        pthread_cond_destroy(&p.work_avail);
    }
    if (c1) {
        pthread_cond_destroy(&p.slot_free);
    }
    if (mutex_ready) {
        pthread_mutex_destroy(&p.mtx);
    }
    if (p.slots != NULL) {
        for (i = 0; i < nslots; i++) {
            if (p.slots[i].in != NULL) {
                secure_clear(p.slots[i].in, in_cap);
                free(p.slots[i].in);
            }
            if (p.slots[i].out != NULL) {
                secure_clear(p.slots[i].out, out_cap);
                free(p.slots[i].out);
            }
        }
        free(p.slots);
    }
    free(p.queue);

    return result;
}

static suw_result_t check_key_does_not_exist(const char *key_path)
{
    if (key_path == NULL) {
        return SUW_ERR_INVALID_ARGUMENT;
    }

    if (access(key_path, F_OK) == 0) {
        return SUW_ERR_KEY_ALREADY_EXISTS;
    }

    if (errno != ENOENT) {
        return SUW_ERR_KEY_OPEN_FAILED;
    }

    return SUW_OK;
}

static suw_result_t create_and_write_key(const char *key_path, uint8_t key[SUW_KEY_SIZE])
{
    if (key_path == NULL || key == NULL) {
        return SUW_ERR_INVALID_ARGUMENT;
    }

    if (getentropy(key, SUW_KEY_SIZE) != 0) {
        return SUW_ERR_ENTROPY_FAILED;
    }

    int fd = open(key_path,
                  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                  S_IRUSR | S_IWUSR);
    if (fd < 0) {
        if (errno == EEXIST) {
            return SUW_ERR_KEY_ALREADY_EXISTS;
        }
        return SUW_ERR_KEY_OPEN_FAILED;
    }

    suw_result_t result = write_all_fd(fd, key, SUW_KEY_SIZE);

    if (close(fd) != 0 && result == SUW_OK) {
        result = SUW_ERR_KEY_WRITE_FAILED;
    }

    return result;
}

static suw_result_t read_key(const char *key_path, uint8_t key[SUW_KEY_SIZE])
{
    if (key_path == NULL || key == NULL) {
        return SUW_ERR_INVALID_ARGUMENT;
    }

    int fd = open(key_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) {
            return SUW_ERR_KEY_NOT_FOUND;
        }
        return SUW_ERR_KEY_OPEN_FAILED;
    }

    suw_result_t result = read_exact_fd(fd, key, SUW_KEY_SIZE);

    if (result == SUW_OK) {
        uint8_t extra;
        ssize_t n;

        do {
            n = read(fd, &extra, 1);
        } while (n < 0 && errno == EINTR);

        if (n < 0) {
            result = SUW_ERR_KEY_READ_FAILED;
        } else if (n != 0) {
            result = SUW_ERR_KEY_INVALID_SIZE;
        }
    }

    if (close(fd) != 0 && result == SUW_OK) {
        result = SUW_ERR_KEY_READ_FAILED;
    }

    return result;
}

static suw_result_t make_tmp_path(const char *output_path, char **tmp_path)
{
    int needed;

    if (output_path == NULL || tmp_path == NULL) {
        return SUW_ERR_INVALID_ARGUMENT;
    }

    needed = snprintf(NULL, 0, "%s.tmp.%ld", output_path, (long)getpid());
    if (needed < 0) {
        return SUW_ERR_INTERNAL;
    }

    *tmp_path = malloc((size_t)needed + 1);
    if (*tmp_path == NULL) {
        return SUW_ERR_MEMORY_ALLOCATION_FAILED;
    }

    snprintf(*tmp_path, (size_t)needed + 1, "%s.tmp.%ld", output_path, (long)getpid());

    return SUW_OK;
}

static suw_result_t open_output(const char *output_path, suw_output_t *out)
{
    if (out == NULL) {
        return SUW_ERR_INVALID_ARGUMENT;
    }

    memset(out, 0, sizeof(*out));

    if (output_path == NULL) {
        out->fp = stdout;
        out->should_close = 0;
        return SUW_OK;
    }

    if (access(output_path, F_OK) == 0) {
        return SUW_ERR_OUTPUT_ALREADY_EXISTS;
    }

    if (errno != ENOENT) {
        return SUW_ERR_OUTPUT_OPEN_FAILED;
    }

    suw_result_t result = make_tmp_path(output_path, &out->tmp_path);
    if (result != SUW_OK) {
        return result;
    }

    int fd = open(out->tmp_path,
                  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0) {
        free(out->tmp_path);
        out->tmp_path = NULL;

        if (errno == EEXIST) {
            return SUW_ERR_OUTPUT_ALREADY_EXISTS;
        }

        return SUW_ERR_OUTPUT_OPEN_FAILED;
    }

    out->fp = fdopen(fd, "wb");
    if (out->fp == NULL) {
        close(fd);
        unlink(out->tmp_path);
        free(out->tmp_path);
        out->tmp_path = NULL;
        return SUW_ERR_OUTPUT_OPEN_FAILED;
    }

    out->final_path = output_path;
    out->should_close = 1;

    return SUW_OK;
}

static suw_result_t commit_output(suw_output_t *out)
{
    if (out == NULL || out->fp == NULL) {
        return SUW_ERR_INVALID_ARGUMENT;
    }

    if (fflush(out->fp) != 0) {
        return SUW_ERR_OUTPUT_WRITE_FAILED;
    }

    if (out->should_close) {
        if (fclose(out->fp) != 0) {
            out->fp = NULL;
            return SUW_ERR_OUTPUT_CLOSE_FAILED;
        }

        out->fp = NULL;

        if (rename(out->tmp_path, out->final_path) != 0) {
            unlink(out->tmp_path);
            free(out->tmp_path);
            out->tmp_path = NULL;
            return SUW_ERR_OUTPUT_RENAME_FAILED;
        }

        out->committed = 1;
    }

    free(out->tmp_path);
    out->tmp_path = NULL;

    return SUW_OK;
}

static void abort_output(suw_output_t *out)
{
    if (out == NULL) {
        return;
    }

    if (out->fp != NULL && out->should_close) {
        fclose(out->fp);
        out->fp = NULL;
    }

    if (!out->committed && out->tmp_path != NULL) {
        unlink(out->tmp_path);
    }

    free(out->tmp_path);
    out->tmp_path = NULL;
}

suw_result_t encrypt_stream(FILE *input, const char *output_path, const char *key_path)
{
    if (input == NULL || key_path == NULL) {
        return SUW_ERR_INVALID_ARGUMENT;
    }

    suw_result_t result = SUW_OK;
    uint8_t key[SUW_KEY_SIZE] = {0};
    uint8_t salt[SUW_SALT_SIZE] = {0};

    suw_output_t output;

    result = check_key_does_not_exist(key_path);
    if (result != SUW_OK) {
        return result;
    }

    result = open_output(output_path, &output);
    if (result != SUW_OK) {
        return result;
    }

    result = create_and_write_key(key_path, key);
    if (result != SUW_OK) {
        goto done;
    }

    /* Fresh per-file salt, written as a header and bound into every chunk. */
    if (getentropy(salt, sizeof(salt)) != 0) {
        result = SUW_ERR_ENTROPY_FAILED;
        goto done;
    }

    result = write_all_file(output.fp, salt, sizeof(salt));
    if (result != SUW_OK) {
        goto done;
    }

    KeccakWidth1600_DWrapInstance dww;
    SHAKE_Wrap_Initialize(&dww, key, sizeof(key), SUW_TAGLEN, SUW_RHO, SUW_CAPACITY);

    result = suw_run_pipeline(input, &output, &dww, salt, 0);

done:
    if (result == SUW_OK) {
        result = commit_output(&output);
    } else {
        abort_output(&output);
    }

    secure_clear(key, sizeof(key));
    secure_clear(salt, sizeof(salt));

    return result;
}

suw_result_t decrypt_stream(FILE *input, const char *output_path, const char *key_path)
{
    if (input == NULL || key_path == NULL) {
        return SUW_ERR_INVALID_ARGUMENT;
    }

    suw_result_t result = SUW_OK;
    uint8_t key[SUW_KEY_SIZE] = {0};
    uint8_t salt[SUW_SALT_SIZE] = {0};

    suw_output_t output;

    result = read_key(key_path, key);
    if (result != SUW_OK) {
        secure_clear(key, sizeof(key));
        return result;
    }

    result = open_output(output_path, &output);
    if (result != SUW_OK) {
        secure_clear(key, sizeof(key));
        return result;
    }

    /* Read the per-file salt header. */
    {
        size_t salt_len = 0;
        int salt_eof = 0;

        result = read_full_or_eof(input, salt, sizeof(salt), &salt_len, &salt_eof);
        if (result == SUW_OK && salt_len != sizeof(salt)) {
            result = SUW_ERR_INVALID_CIPHERTEXT;
        }
        if (result != SUW_OK) {
            goto done;
        }
    }

    KeccakWidth1600_DWrapInstance dwu;
    SHAKE_Wrap_Initialize(&dwu, key, sizeof(key), SUW_TAGLEN, SUW_RHO, SUW_CAPACITY);

    result = suw_run_pipeline(input, &output, &dwu, salt, 1);

done:
    if (result == SUW_OK) {
        result = commit_output(&output);
    } else {
        abort_output(&output);
    }

    secure_clear(key, sizeof(key));
    secure_clear(salt, sizeof(salt));

    return result;
}

#endif /* XKCP_has_ShakingUpAE */
