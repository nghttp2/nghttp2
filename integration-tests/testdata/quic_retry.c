/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <ngtcp2/ngtcp2.h>
#define REAL(name) ((__typeof__(&name))dlsym(RTLD_NEXT, #name))
static int injected, classify;
static ngtcp2_conn *retry_conn;
static void record(const char *s) {
  FILE *f = fopen(getenv("NGHTTP2_TEST_RECORD"), "a");
  if (!f)
    abort();
  fprintf(f, "%s\n", s);
  fclose(f);
}
int ngtcp2_conn_read_pkt_versioned(ngtcp2_conn *conn, const ngtcp2_path *path,
                                   int version, const ngtcp2_pkt_info *pi,
                                   const uint8_t *data, size_t len,
                                   ngtcp2_tstamp ts) {
  if (!injected) {
    injected = 1;
    retry_conn = conn;
    classify = 1;
    record("retry-injected");
    return NGTCP2_ERR_RETRY;
  }
  return REAL(ngtcp2_conn_read_pkt_versioned)(conn, path, version, pi, data,
                                              len, ts);
}
void ngtcp2_ccerr_set_liberr(ngtcp2_ccerr *ccerr, int error,
                             const uint8_t *reason, size_t len) {
  REAL(ngtcp2_ccerr_set_liberr)(ccerr, error, reason, len);
  if (classify) {
    classify = 0;
    record(ccerr->type == NGTCP2_CCERR_TYPE_RETRY ? "retry-type-preserved"
                                                  : "retry-type-lost");
  }
}
ngtcp2_ssize ngtcp2_conn_write_connection_close_versioned(
  ngtcp2_conn *conn, ngtcp2_path *path, int version, ngtcp2_pkt_info *pi,
  uint8_t *dest, size_t len, const ngtcp2_ccerr *ccerr, ngtcp2_tstamp ts) {
  if (conn == retry_conn)
    record("retry-connection-closed");
  return REAL(ngtcp2_conn_write_connection_close_versioned)(
    conn, path, version, pi, dest, len, ccerr, ts);
}
void ngtcp2_conn_del(ngtcp2_conn *conn) {
  if (conn == retry_conn) {
    record("retry-connection-deleted");
    retry_conn = NULL;
  }
  REAL(ngtcp2_conn_del)(conn);
}
