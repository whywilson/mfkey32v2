#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include "parity.h"
#include "crapto1.h"
#include "mfkey.h"
#include "mfkey32.h"

#include "unistd.h"
#include <sys/param.h>


#define MEM_CHUNK 10000
#define TRY_KEYS 50

typedef struct
{
  uint32_t ntp;
  uint32_t ks1;
} NtpKs1;

typedef struct
{
  NtpKs1 *pNK;
  uint32_t authuid;

  uint64_t *keys;
  uint32_t keyCount;

  uint32_t startPos;
  uint32_t endPos;
} RecPar;

int uint64_compare(const void *a, const void *b)
{
  return (*(uint64_t *)a > *(uint64_t *)b) - (*(uint64_t *)a < *(uint64_t *)b);
}

uint64_t *most_frequent_uint64(uint64_t *keys, uint32_t size, uint32_t *outputKeyCount)
{
  uint64_t i, maxFreq = 1, currentFreq = 1, currentItem = keys[0];
  uint64_t *output = calloc(size, sizeof(uint64_t));
  qsort(keys, size, sizeof(uint64_t), uint64_compare);

  for (i = 1; i < size; i++)
  {
    if (keys[i] == keys[i - 1])
    {
      currentFreq++;
    }
    else
    {
      if (currentFreq > maxFreq)
      {
        maxFreq = currentFreq;
      }
      currentFreq = 1;
    }
  }
  if (currentFreq > maxFreq)
  {
    maxFreq = currentFreq;
  }

  currentItem = keys[0];
  currentFreq = 1;
  for (i = 1; i <= size; i++)
  {
    if (i < size && keys[i] == keys[i - 1])
    {
      currentFreq++;
    }
    else
    {
      if (currentFreq == maxFreq)
      {
        output[*outputKeyCount] = currentItem;
        *outputKeyCount += 1;
      }
      if (i < size)
      {
        currentItem = keys[i];
        currentFreq = 1;
      }
    }
  }

  return output;
}

// Return 1 if the nonce is invalid else return 0
static uint8_t valid_nonce(uint32_t Nt, uint32_t NtEnc, uint32_t Ks1, uint8_t *parity)
{
  return (
             (oddparity8((Nt >> 24) & 0xFF) == ((parity[0]) ^ oddparity8((NtEnc >> 24) & 0xFF) ^ BIT(Ks1, 16))) &&
             (oddparity8((Nt >> 16) & 0xFF) == ((parity[1]) ^ oddparity8((NtEnc >> 16) & 0xFF) ^ BIT(Ks1, 8))) &&
             (oddparity8((Nt >> 8) & 0xFF) == ((parity[2]) ^ oddparity8((NtEnc >> 8) & 0xFF) ^ BIT(Ks1, 0))))
             ? 1
             : 0;
}

FFI_PLUGIN_EXPORT uint64_t mfkey32(Mfkey32 *data)
{
  struct Crypto1State *s, *t;
  uint64_t key; // recovered key
  uint64_t ks2;

  // Generate lfsr successors of the tag challenge
  uint32_t p64 = prng_successor(data->nt0, 64);
  uint32_t p64b = prng_successor(data->nt1, 64);

  ks2 = data->ar0_enc ^ p64;

  s = lfsr_recovery32(data->ar0_enc ^ p64, 0);

  for (t = s; t->odd | t->even; ++t)
  {
    lfsr_rollback_word(t, 0, 0);
    lfsr_rollback_word(t, data->nr0_enc, 1);
    lfsr_rollback_word(t, data->uid ^ data->nt0, 0);
    crypto1_get_lfsr(t, &key);

    crypto1_word(t, data->uid ^ data->nt1, 0);
    crypto1_word(t, data->nr1_enc, 1);
    if (data->ar1_enc == (crypto1_word(t, 0, 0) ^ p64b))
    {
      free(s);
      return key;
    }
  }

  free(s);
  return UINT64_MAX;
}