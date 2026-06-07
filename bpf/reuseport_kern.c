/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2021 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include <linux/udp.h>
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

/*
 * How to compile:
 *
 * clang-12 -O2 -Wall -target bpf -g -c reuseport_kern.c -o reuseport_kern.o \
 *   -I/path/to/kernel/include
 *
 * See
 * https://www.kernel.org/doc/Documentation/kbuild/headers_install.txt
 * how to install kernel header files.
 */

/* AES_CBC_decrypt_buffer: https://github.com/kokke/tiny-AES-c
   License is Public Domain.  Commit hash:
   12e7744b4919e9d55de75b7ab566326a1c8e7a67 */

#define AES_keyExpSize 176

struct AES_ctx {
  __u8 RoundKey[AES_keyExpSize];
};

/* The number of columns comprising a state in AES. This is a constant
   in AES. Value=4 */
#define Nb 4

#define Nr 10 /* The number of rounds in AES Cipher. */

/* state - array holding the intermediate results during
   decryption. */
typedef __u8 state_t[4][4];

/* The lookup-tables are marked const so they can be placed in
   read-only storage instead of RAM The numbers below can be computed
   dynamically trading ROM for RAM - This can be useful in (embedded)
   bootloader applications, where ROM is often limited. */
static const __u8 rsbox[256] = {
  0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81,
  0xF3, 0xD7, 0xFB, 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E,
  0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23,
  0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E, 0x08, 0x2E, 0xA1, 0x66,
  0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25, 0x72,
  0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65,
  0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46,
  0x57, 0xA7, 0x8D, 0x9D, 0x84, 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
  0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA,
  0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, 0x3A, 0x91,
  0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6,
  0x73, 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8,
  0x1C, 0x75, 0xDF, 0x6E, 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F,
  0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2,
  0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4, 0x1F, 0xDD, 0xA8,
  0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
  0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93,
  0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB,
  0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6,
  0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
};

/* This function adds the round key to state.  The round key is added
   to the state by an XOR function. */
static void AddRoundKey(__u8 round, state_t *state, const __u8 *RoundKey) {
  __u8 i, j;
  for (i = 0; i < 4; ++i) {
    for (j = 0; j < 4; ++j) {
      (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
    }
  }
}

static __u8 xtime(__u8 x) { return ((x << 1) ^ (((x >> 7) & 1) * 0x1B)); }

#define Multiply(x, y)                                                         \
  (((y & 1) * x) ^ ((y >> 1 & 1) * xtime(x)) ^                                 \
   ((y >> 2 & 1) * xtime(xtime(x))) ^                                          \
   ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^                                   \
   ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))))

#define getSBoxInvert(num) (rsbox[(num)])

/* MixColumns function mixes the columns of the state matrix.  The
   method used to multiply may be difficult to understand for the
   inexperienced. Please use the references to gain more
   information. */
static void InvMixColumns(state_t *state) {
  int i;
  __u8 a, b, c, d;
  for (i = 0; i < 4; ++i) {
    a = (*state)[i][0];
    b = (*state)[i][1];
    c = (*state)[i][2];
    d = (*state)[i][3];

    (*state)[i][0] = Multiply(a, 0x0E) ^ Multiply(b, 0x0B) ^ Multiply(c, 0x0D) ^
                     Multiply(d, 0x09);
    (*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0E) ^ Multiply(c, 0x0B) ^
                     Multiply(d, 0x0D);
    (*state)[i][2] = Multiply(a, 0x0D) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0E) ^
                     Multiply(d, 0x0B);
    (*state)[i][3] = Multiply(a, 0x0B) ^ Multiply(b, 0x0D) ^ Multiply(c, 0x09) ^
                     Multiply(d, 0x0E);
  }
}

extern __u32 LINUX_KERNEL_VERSION __kconfig;

/* The SubBytes Function Substitutes the values in the state matrix
   with values in an S-box. */
static void InvSubBytes(state_t *state) {
  __u8 i, j;
  if (LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 10, 0)) {
    for (i = 0; i < 4; ++i) {
      for (j = 0; j < 4; ++j) {
        /* Ubuntu 20.04 LTS kernel 5.4.0 needs this workaround
           otherwise "math between map_value pointer and register with
           unbounded min value is not allowed".  5.10.0 is a kernel
           version that works but it might not be the minimum
           version.  */
        __u8 k = (*state)[j][i];
        (*state)[j][i] = k ? getSBoxInvert(k) : getSBoxInvert(0);
      }
    }
  } else {
    for (i = 0; i < 4; ++i) {
      for (j = 0; j < 4; ++j) {
        (*state)[j][i] = getSBoxInvert((*state)[j][i]);
      }
    }
  }
}

static void InvShiftRows(state_t *state) {
  __u8 temp;

  /* Rotate first row 1 columns to right */
  temp = (*state)[3][1];
  (*state)[3][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[0][1];
  (*state)[0][1] = temp;

  /* Rotate second row 2 columns to right */
  temp = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  /* Rotate third row 3 columns to right */
  temp = (*state)[0][3];
  (*state)[0][3] = (*state)[1][3];
  (*state)[1][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[3][3];
  (*state)[3][3] = temp;
}

static void InvCipher(state_t *state, const __u8 *RoundKey) {
  /* Add the First round key to the state before starting the
     rounds. */
  AddRoundKey(Nr, state, RoundKey);

  /* There will be Nr rounds.  The first Nr-1 rounds are identical.
     These Nr rounds are executed in the loop below.  Last one without
     InvMixColumn() */
  InvShiftRows(state);
  InvSubBytes(state);
  AddRoundKey(Nr - 1, state, RoundKey);
  InvMixColumns(state);

  InvShiftRows(state);
  InvSubBytes(state);
  AddRoundKey(Nr - 2, state, RoundKey);
  InvMixColumns(state);

  InvShiftRows(state);
  InvSubBytes(state);
  AddRoundKey(Nr - 3, state, RoundKey);
  InvMixColumns(state);

  InvShiftRows(state);
  InvSubBytes(state);
  AddRoundKey(Nr - 4, state, RoundKey);
  InvMixColumns(state);

  InvShiftRows(state);
  InvSubBytes(state);
  AddRoundKey(Nr - 5, state, RoundKey);
  InvMixColumns(state);

  InvShiftRows(state);
  InvSubBytes(state);
  AddRoundKey(Nr - 6, state, RoundKey);
  InvMixColumns(state);

  InvShiftRows(state);
  InvSubBytes(state);
  AddRoundKey(Nr - 7, state, RoundKey);
  InvMixColumns(state);

  InvShiftRows(state);
  InvSubBytes(state);
  AddRoundKey(Nr - 8, state, RoundKey);
  InvMixColumns(state);

  InvShiftRows(state);
  InvSubBytes(state);
  AddRoundKey(Nr - 9, state, RoundKey);
  InvMixColumns(state);

  InvShiftRows(state);
  InvSubBytes(state);
  AddRoundKey(Nr - 10, state, RoundKey);
}

static void AES_ECB_decrypt(const struct AES_ctx *ctx, __u8 *buf) {
  /* The next function call decrypts the PlainText with the Key using
     AES algorithm. */
  InvCipher((state_t *)buf, ctx->RoundKey);
}

/* rol32: From linux kernel source code */

/**
 * rol32 - rotate a 32-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline __u32 rol32(__u32 word, unsigned int shift) {
  return (word << shift) | (word >> ((-shift) & 31));
}

/* jhash.h: Jenkins hash support.
 *
 * Copyright (C) 2006. Bob Jenkins (bob_jenkins@burtleburtle.net)
 *
 * https://burtleburtle.net/bob/hash/
 *
 * These are the credits from Bob's sources:
 *
 * lookup3.c, by Bob Jenkins, May 2006, Public Domain.
 *
 * These are functions for producing 32-bit hashes for hash table lookup.
 * hashword(), hashlittle(), hashlittle2(), hashbig(), mix(), and final()
 * are externally useful functions.  Routines to test the hash are included
 * if SELF_TEST is defined.  You can use this free for any purpose.  It's in
 * the public domain.  It has no warranty.
 *
 * Copyright (C) 2009-2010 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
 *
 * I've modified Bob's hash to be useful in the Linux kernel, and
 * any bugs present are my fault.
 * Jozsef
 */

/* __jhash_final - final mixing of 3 32-bit values (a,b,c) into c */
#define __jhash_final(a, b, c)                                                 \
  {                                                                            \
    c ^= b;                                                                    \
    c -= rol32(b, 14);                                                         \
    a ^= c;                                                                    \
    a -= rol32(c, 11);                                                         \
    b ^= a;                                                                    \
    b -= rol32(a, 25);                                                         \
    c ^= b;                                                                    \
    c -= rol32(b, 16);                                                         \
    a ^= c;                                                                    \
    a -= rol32(c, 4);                                                          \
    b ^= a;                                                                    \
    b -= rol32(a, 14);                                                         \
    c ^= b;                                                                    \
    c -= rol32(b, 24);                                                         \
  }

/* __jhash_nwords - hash exactly 3, 2 or 1 word(s) */
static inline __u32 __jhash_nwords(__u32 a, __u32 b, __u32 c, __u32 initval) {
  a += initval;
  b += initval;
  c += initval;

  __jhash_final(a, b, c);

  return c;
}

/* An arbitrary initial parameter */
#define JHASH_INITVAL 0xDEADBEEF

static inline __u32 jhash_2words(__u32 a, __u32 b, __u32 initval) {
  return __jhash_nwords(a, b, 0, initval + JHASH_INITVAL + (2 << 2));
}

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 255);
  __type(key, __u64);
  __type(value, __u32);
} worker_id_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
  __uint(max_entries, 255);
  __type(key, __u32);
  __type(value, __u32);
} reuseport_array SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} sk_info SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct AES_ctx);
} aes_key SEC(".maps");

typedef struct quic_hd {
  __u8 *dcid;
  __u32 dcidlen;
  __u32 dcid_offset;
  __u8 type;
} quic_hd;

#define SV_DCIDLEN 17
#define MAX_DCIDLEN 20
#define MIN_DCIDLEN 8
#define WORKER_IDLEN 8
#define WORKER_ID_OFFSET 1

enum {
  NGTCP2_PKT_INITIAL = 0x0,
  NGTCP2_PKT_0RTT = 0x1,
  NGTCP2_PKT_HANDSHAKE = 0x2,
  NGTCP2_PKT_SHORT = 0x40,
};

static inline int parse_quic(quic_hd *qhd, __u8 *data, __u8 *data_end) {
  __u8 *p;
  __u64 dcidlen;

  if (*data & 0x80) {
    p = data + 1 + 4;

    /* Do not check the actual DCID length because we might not buffer
       entire DCID here. */
    dcidlen = *p;

    if (dcidlen > MAX_DCIDLEN || dcidlen < MIN_DCIDLEN) {
      return -1;
    }

    ++p;

    qhd->type = (*data & 0x30) >> 4;
    qhd->dcid = p;
    qhd->dcidlen = dcidlen;
    qhd->dcid_offset = 6;
  } else {
    qhd->type = NGTCP2_PKT_SHORT;
    qhd->dcid = data + 1;
    qhd->dcidlen = SV_DCIDLEN;
    qhd->dcid_offset = 1;
  }

  return 0;
}

static __u32 hash(const __u8 *data, __u32 datalen, __u32 initval) {
  __u32 a, b;

  a = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
  b = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];

  return jhash_2words(a, b, initval);
}

static __u32 sk_index_from_dcid(const quic_hd *qhd,
                                const struct sk_reuseport_md *reuse_md,
                                __u64 num_socks) {
  __u32 len = qhd->dcidlen;
  __u32 h = reuse_md->hash;
  __u8 hbuf[8];

  if (len > 16) {
    __builtin_memset(hbuf, 0, sizeof(hbuf));

    switch (len) {
    case 20:
      __builtin_memcpy(hbuf, qhd->dcid + 16, 4);
      break;
    case 19:
      __builtin_memcpy(hbuf, qhd->dcid + 16, 3);
      break;
    case 18:
      __builtin_memcpy(hbuf, qhd->dcid + 16, 2);
      break;
    case 17:
      __builtin_memcpy(hbuf, qhd->dcid + 16, 1);
      break;
    }

    h = hash(hbuf, sizeof(hbuf), h);
    len = 16;
  }

  if (len > 8) {
    __builtin_memset(hbuf, 0, sizeof(hbuf));

    switch (len) {
    case 16:
      __builtin_memcpy(hbuf, qhd->dcid + 8, 8);
      break;
    case 15:
      __builtin_memcpy(hbuf, qhd->dcid + 8, 7);
      break;
    case 14:
      __builtin_memcpy(hbuf, qhd->dcid + 8, 6);
      break;
    case 13:
      __builtin_memcpy(hbuf, qhd->dcid + 8, 5);
      break;
    case 12:
      __builtin_memcpy(hbuf, qhd->dcid + 8, 4);
      break;
    case 11:
      __builtin_memcpy(hbuf, qhd->dcid + 8, 3);
      break;
    case 10:
      __builtin_memcpy(hbuf, qhd->dcid + 8, 2);
      break;
    case 9:
      __builtin_memcpy(hbuf, qhd->dcid + 8, 1);
      break;
    }

    h = hash(hbuf, sizeof(hbuf), h);
    len = 8;
  }

  return hash(qhd->dcid, len, h) % num_socks;
}

SEC("sk_reuseport")
int select_reuseport(struct sk_reuseport_md *reuse_md) {
  __u32 sk_index, *psk_index;
  __u64 *pnum_socks;
  __u32 zero = 0;
  int rv;
  quic_hd qhd;
  __u8 qpktbuf[6 + MAX_DCIDLEN];
  struct AES_ctx *aes_ctx;
  __u8 *worker_id;
  __u16 remote_port;
  __u8 *data = reuse_md->data;

  /* Packets less than 22 bytes never be a valid QUIC packet. */
  if (reuse_md->len < sizeof(struct udphdr) + 22) {
    return SK_DROP;
  }

  if (reuse_md->data + sizeof(struct udphdr) > reuse_md->data_end) {
    return SK_DROP;
  }

  remote_port = (data[0] << 8) + data[1];

  switch (remote_port) {
  case 1900:
  case 5353:
  case 11211:
  case 20800:
  case 27015:
    return SK_DROP;
  default:
    if (remote_port < 1024) {
      return SK_DROP;
    }
  }

  if (bpf_skb_load_bytes(reuse_md, sizeof(struct udphdr), qpktbuf,
                         sizeof(qpktbuf)) != 0) {
    return SK_DROP;
  }

  pnum_socks = bpf_map_lookup_elem(&sk_info, &zero);
  if (pnum_socks == NULL) {
    return SK_DROP;
  }

  aes_ctx = bpf_map_lookup_elem(&aes_key, &zero);
  if (aes_ctx == NULL) {
    return SK_DROP;
  }

  rv = parse_quic(&qhd, qpktbuf, qpktbuf + sizeof(qpktbuf));
  if (rv != 0) {
    return SK_DROP;
  }

  switch (qhd.type) {
  case NGTCP2_PKT_INITIAL:
  case NGTCP2_PKT_0RTT:
    if (qhd.dcidlen == SV_DCIDLEN) {
      worker_id = qhd.dcid + WORKER_ID_OFFSET;
      AES_ECB_decrypt(aes_ctx, worker_id);

      psk_index = bpf_map_lookup_elem(&worker_id_map, worker_id);
      if (psk_index != NULL) {
        sk_index = *psk_index;

        break;
      }
    }

    sk_index = sk_index_from_dcid(&qhd, reuse_md, *pnum_socks);

    break;
  case NGTCP2_PKT_HANDSHAKE:
  case NGTCP2_PKT_SHORT:
    if (qhd.dcidlen != SV_DCIDLEN) {
      return SK_DROP;
    }

    worker_id = qhd.dcid + WORKER_ID_OFFSET;
    AES_ECB_decrypt(aes_ctx, worker_id);

    psk_index = bpf_map_lookup_elem(&worker_id_map, worker_id);
    if (psk_index == NULL) {
      sk_index = sk_index_from_dcid(&qhd, reuse_md, *pnum_socks);

      break;
    }

    sk_index = *psk_index;

    break;
  default:
    return SK_DROP;
  }

  rv = bpf_sk_select_reuseport(reuse_md, &reuseport_array, &sk_index, 0);
  if (rv != 0) {
    return SK_DROP;
  }

  return SK_PASS;
}
