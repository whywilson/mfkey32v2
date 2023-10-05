#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <pthread.h>
#include <unistd.h>

#define FFI_PLUGIN_EXPORT

typedef struct
{
    uint32_t uid;     // serial number
    uint32_t nt0;     // tag challenge first
    uint32_t nt1;     // tag challenge second
    uint32_t nr0_enc; // first encrypted reader challenge
    uint32_t ar0_enc; // first encrypted reader response
    uint32_t nr1_enc; // second encrypted reader challenge
    uint32_t ar1_enc; // second encrypted reader response
} Mfkey32;


FFI_PLUGIN_EXPORT uint64_t mfkey32(Mfkey32 *data);