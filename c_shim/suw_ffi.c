/*
 * Thin C shim exposing a stable, struct-agnostic ABI over XKCP's ShakingUpAE
 * DWrap interface. The Rust side keeps the opaque instance as a byte buffer of
 * size suw_dwrap_size(), so it never has to mirror the C struct layout.
 */
#include "ShakingUpAE.h"

#include <stddef.h>
#include <stdint.h>

size_t suw_dwrap_size(void)
{
    return sizeof(KeccakWidth1600_DWrapInstance);
}

void suw_dwrap_init(void *D, const uint8_t *k, unsigned int klen,
                    unsigned int taglen, unsigned int rho, unsigned int c)
{
    SHAKE_Wrap_Initialize((KeccakWidth1600_DWrapInstance *)D, k, klen, taglen, rho, c);
}

void suw_dwrap_clone(void *dst, const void *src)
{
    SHAKE_Wrap_Clone((KeccakWidth1600_DWrapInstance *)dst,
                     (const KeccakWidth1600_DWrapInstance *)src);
}

void suw_dwrap_wrap(void *D, uint8_t *C, const uint8_t *A, size_t Alen,
                    const uint8_t *P, size_t Plen)
{
    SHAKE_Wrap_Wrap((KeccakWidth1600_DWrapInstance *)D, C, A, Alen, P, Plen);
}

int suw_dwrap_unwrap(void *D, uint8_t *P, const uint8_t *A, size_t Alen,
                     const uint8_t *C, size_t Clen)
{
    return SHAKE_Wrap_Unwrap((KeccakWidth1600_DWrapInstance *)D, P, A, Alen, C, Clen);
}
