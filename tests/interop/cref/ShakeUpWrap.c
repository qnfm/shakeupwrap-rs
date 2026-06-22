#define _GNU_SOURCE

#include "config.h"

#ifdef XKCP_has_ShakingUpAE

#include "suw.h"

#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

typedef enum {
    MODE_NONE = 0,
    MODE_ENCRYPT,
    MODE_DECRYPT
} suw_mode_t;

typedef struct {
    suw_mode_t mode;
    const char *key_path;
    const char *out_path;
} suw_args_t;

static void print_usage(FILE *f)
{
    fprintf(f,
        "Usage:\n"
        "  ShakeUpWrap -e -k KEYFILE [-o OUTFILE]\n"
        "  ShakeUpWrap -d -k KEYFILE [-o OUTFILE]\n"
        "\n"
        "Options:\n"
        "  -e, --encrypt       Encrypt stdin to stdout or OUTFILE\n"
        "  -d, --decrypt       Decrypt stdin to stdout or OUTFILE\n"
        "  -k, --key KEYFILE   Key file path\n"
        "  -o, --output FILE   Output file path\n"
        "  -h, --help          Show this help\n");
}

static suw_result_t parse_args(int argc, char **argv, suw_args_t *args)
{
    static const struct option long_options[] = {
        {"encrypt", no_argument,       NULL, 'e'},
        {"decrypt", no_argument,       NULL, 'd'},
        {"key",     required_argument, NULL, 'k'},
        {"output",  required_argument, NULL, 'o'},
        {"help",    no_argument,       NULL, 'h'},
        {0, 0, 0, 0}
    };

    if (args == NULL) {
        return SUW_ERR_INVALID_ARGUMENT;
    }

    args->mode = MODE_NONE;
    args->key_path = NULL;
    args->out_path = NULL;

    int opt;

    while ((opt = getopt_long(argc, argv, "edk:o:h", long_options, NULL)) != -1) {
        switch (opt) {
        case 'e':
            if (args->mode != MODE_NONE) {
                return SUW_ERR_MULTIPLE_MODES;
            }
            args->mode = MODE_ENCRYPT;
            break;

        case 'd':
            if (args->mode != MODE_NONE) {
                return SUW_ERR_MULTIPLE_MODES;
            }
            args->mode = MODE_DECRYPT;
            break;

        case 'k':
            args->key_path = optarg;
            break;

        case 'o':
            args->out_path = optarg;
            break;

        case 'h':
            print_usage(stdout);
            exit(EXIT_SUCCESS);

        default:
            return SUW_ERR_INVALID_ARGUMENT;
        }
    }

    if (optind != argc) {
        return SUW_ERR_UNEXPECTED_POSITIONAL_ARGUMENT;
    }

    if (args->mode == MODE_NONE) {
        return SUW_ERR_MISSING_MODE;
    }

    if (args->key_path == NULL) {
        return SUW_ERR_MISSING_KEY_PATH;
    }

    return SUW_OK;
}

int main(int argc, char **argv)
{
    suw_args_t args;
    suw_result_t result = parse_args(argc, argv, &args);

    if (result != SUW_OK) {
        fprintf(stderr, "Error: %s\n\n", suw_result_message(result));
        print_usage(stderr);
        return EXIT_FAILURE;
    }

    if (args.mode == MODE_ENCRYPT) {
        result = encrypt_stream(stdin, args.out_path, args.key_path);
    } else {
        result = decrypt_stream(stdin, args.out_path, args.key_path);
    }

    if (result != SUW_OK) {
        fprintf(stderr, "Error: %s\n", suw_result_message(result));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

#else

#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    fprintf(stderr, "ShakeUpWrap is not available: XKCP_has_ShakingUpAE is not enabled\n");
    return EXIT_FAILURE;
}

#endif
