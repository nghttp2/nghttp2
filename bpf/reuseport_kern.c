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
#define JHASH_INITVAL 0xdeadbeef

static inline __u32 jhash_2words(__u32 a, __u32 b, __u32 initval) {
  return __jhash_nwords(a, b, 0, initval + JHASH_INITVAL + (2 << 2));
}

struct bpf_map_def SEC("maps") cid_prefix_map = {
    .type = BPF_MAP_TYPE_HASH,
    .max_entries = 255,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u32),
};

struct bpf_map_def SEC("maps") reuseport_array = {
    .type = BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
    .max_entries = 255,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
};

struct bpf_map_def SEC("maps") sk_info = {
    .type = BPF_MAP_TYPE_ARRAY,
    .max_entries = 1,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
};

typedef struct quic_hd {
  const __u8 *dcid;
  __u32 dcidlen;
  __u32 dcid_offset;
  __u8 type;
} quic_hd;

#define SV_DCIDLEN 20
#define MAX_DCIDLEN 20
#define MIN_DCIDLEN 8
#define CID_PREFIXLEN 8

enum {
  NGTCP2_PKT_INITIAL = 0x0,
  NGTCP2_PKT_0RTT = 0x1,
  NGTCP2_PKT_HANDSHAKE = 0x2,
  NGTCP2_PKT_SHORT = 0x40,
};

static inline int parse_quic(quic_hd *qhd, const __u8 *data,
                             const __u8 *data_end) {
  const __u8 *p;
  __u64 dcidlen;

  if (*data & 0x80) {
    p = data + 1 + 4;

    // Do not check the actual DCID length because we might not buffer
    // whole DCID here.
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

SEC("sk_reuseport")
int select_reuseport(struct sk_reuseport_md *reuse_md) {
  __u32 sk_index, *psk_index;
  __u8 sk_prefix[8];
  __u32 *pnum_socks;
  __u32 zero = 0;
  int rv;
  quic_hd qhd;
  __u32 a, b;
  __u8 pkt_databuf[6 + MAX_DCIDLEN];

  if (bpf_skb_load_bytes(reuse_md, sizeof(struct udphdr), pkt_databuf,
                         sizeof(pkt_databuf)) != 0) {
    return SK_DROP;
  }

  rv = parse_quic(&qhd, pkt_databuf, pkt_databuf + sizeof(pkt_databuf));
  if (rv != 0) {
    return SK_DROP;
  }

  switch (qhd.type) {
  case NGTCP2_PKT_INITIAL:
  case NGTCP2_PKT_0RTT:
    __builtin_memcpy(sk_prefix, pkt_databuf + qhd.dcid_offset, CID_PREFIXLEN);

    if (qhd.dcidlen == SV_DCIDLEN) {
      psk_index = bpf_map_lookup_elem(&cid_prefix_map, sk_prefix);
      if (psk_index != NULL) {
        sk_index = *psk_index;
        break;
      }
    }

    pnum_socks = bpf_map_lookup_elem(&sk_info, &zero);
    if (pnum_socks == NULL) {
      return SK_DROP;
    }

    a = (sk_prefix[0] << 24) | (sk_prefix[1] << 16) | (sk_prefix[2] << 8) |
        sk_prefix[3];
    b = (sk_prefix[4] << 24) | (sk_prefix[5] << 16) | (sk_prefix[6] << 8) |
        sk_prefix[7];

    sk_index = jhash_2words(a, b, reuse_md->hash) % *pnum_socks;

    break;
  case NGTCP2_PKT_HANDSHAKE:
  case NGTCP2_PKT_SHORT:
    if (qhd.dcidlen != SV_DCIDLEN) {
      return SK_DROP;
    }

    __builtin_memcpy(sk_prefix, pkt_databuf + qhd.dcid_offset, CID_PREFIXLEN);

    psk_index = bpf_map_lookup_elem(&cid_prefix_map, sk_prefix);
    if (psk_index == NULL) {
      pnum_socks = bpf_map_lookup_elem(&sk_info, &zero);
      if (pnum_socks == NULL) {
        return SK_DROP;
      }

      a = (sk_prefix[0] << 24) | (sk_prefix[1] << 16) | (sk_prefix[2] << 8) |
          sk_prefix[3];
      b = (sk_prefix[4] << 24) | (sk_prefix[5] << 16) | (sk_prefix[6] << 8) |
          sk_prefix[7];

      sk_index = jhash_2words(a, b, reuse_md->hash) % *pnum_socks;

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
