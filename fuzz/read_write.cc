#include <array>
#include <span>
#include <string_view>
#include <print>

#include <fuzzer/FuzzedDataProvider.h>

#include <nghttp2v2/nghttp2.h>

using namespace std::literals;

namespace {
nghttp2_mem setup_mem(FuzzedDataProvider &fdp) {
  return nghttp2_mem{
    .user_data = &fdp,
    .malloc =
      [](size_t size, void *user_data) {
        auto fdp = static_cast<FuzzedDataProvider *>(user_data);
        return fdp->ConsumeBool() ? nullptr : malloc(size);
      },
    .free = [](void *ptr, void *user_data) { free(ptr); },
    .calloc =
      [](size_t nmemb, size_t size, void *user_data) {
        auto fdp = static_cast<FuzzedDataProvider *>(user_data);
        return fdp->ConsumeBool() ? nullptr : calloc(nmemb, size);
      },
    .realloc =
      [](void *ptr, size_t size, void *user_data) {
        auto fdp = static_cast<FuzzedDataProvider *>(user_data);
        return fdp->ConsumeBool() ? nullptr : realloc(ptr, size);
      },
  };
}
} // namespace

namespace {
int simple_stream_callback(nghttp2_conn *conn, int64_t stream_id,
                           void *user_data,
                           std::initializer_list<const int> retvals = {
                             0,
                             NGHTTP2_ERR_CALLBACK_FAILURE,
                           }) {
  auto fdp = static_cast<FuzzedDataProvider *>(user_data);

  if (fdp->ConsumeBool()) {
    nghttp2_conn_shutdown_stream(conn, 0x00, stream_id, NGHTTP2_NO_ERROR);
  }

  if (fdp->ConsumeBool()) {
    nghttp2_conn_terminate(conn, NGHTTP2_NO_ERROR);
  }

  return fdp->PickValueInArray(std::move(retvals));
}
} // namespace

namespace {
int simple_callback(nghttp2_conn *conn, void *user_data,
                    std::initializer_list<const int> retvals = {
                      0,
                      NGHTTP2_ERR_CALLBACK_FAILURE,
                    }) {
  auto fdp = static_cast<FuzzedDataProvider *>(user_data);

  if (fdp->ConsumeBool()) {
    nghttp2_conn_terminate(conn, NGHTTP2_NO_ERROR);
  }

  return fdp->PickValueInArray(std::move(retvals));
}
} // namespace

namespace {
std::tuple<nghttp2_conn *, bool> setup_conn(FuzzedDataProvider &fdp,
                                            const nghttp2_mem *mem) {
  static constexpr auto callbacks = nghttp2_callbacks{
    .rand = [](uint8_t *dest, size_t destlen) { memset(dest, 0, destlen); },
    .recv_settings =
      [](nghttp2_conn *conn, const nghttp2_proto_settings *settings,
         void *user_data) { return simple_callback(conn, user_data); },
    .stream_open =
      [](nghttp2_conn *conn, int64_t stream_id, void *user_data) {
        return simple_stream_callback(conn, stream_id, user_data);
      },
    .stream_close =
      [](nghttp2_conn *conn, uint32_t flags, int64_t stream_id,
         uint32_t error_code, void *user_data, void *stream_user_data) {
        return simple_stream_callback(conn, stream_id, user_data);
      },
    .extend_max_stream_data =
      [](nghttp2_conn *conn, int64_t stream_id, uint64_t max_data,
         void *user_data, void *stream_user_data) {
        return simple_stream_callback(conn, stream_id, user_data);
      },
    .write_stream_data_offset =
      [](nghttp2_conn *conn, int64_t stream_id, uint64_t offset, size_t len,
         void *user_data, void *stream_user_data) {
        return simple_stream_callback(conn, stream_id, user_data);
      },
    .begin_headers =
      [](nghttp2_conn *conn, int64_t stream_id, void *user_data,
         void *stream_user_data) {
        return simple_stream_callback(conn, stream_id, user_data);
      },
    .recv_header =
      [](nghttp2_conn *conn, int64_t stream_id, int32_t token,
         nghttp2_rcbuf *name, nghttp2_rcbuf *value, uint8_t flags,
         void *user_data, void *stream_user_data) {
        return simple_stream_callback(conn, stream_id, user_data);
      },
    .end_headers =
      [](nghttp2_conn *conn, int64_t stream_id, int fin, void *user_data,
         void *stream_user_data) {
        return simple_stream_callback(conn, stream_id, user_data);
      },
    .begin_trailers =
      [](nghttp2_conn *conn, int64_t stream_id, void *user_data,
         void *stream_user_data) {
        return simple_stream_callback(conn, stream_id, user_data);
      },
    .recv_trailer =
      [](nghttp2_conn *conn, int64_t stream_id, int32_t token,
         nghttp2_rcbuf *name, nghttp2_rcbuf *value, uint8_t flags,
         void *user_data, void *stream_user_data) {
        return simple_stream_callback(conn, stream_id, user_data);
      },
    .end_trailers =
      [](nghttp2_conn *conn, int64_t stream_id, int fin, void *user_data,
         void *stream_user_data) {
        return simple_stream_callback(conn, stream_id, user_data);
      },
    .recv_data =
      [](nghttp2_conn *conn, int64_t stream_id, const uint8_t *data,
         size_t datalen, void *user_data, void *stream_user_data) {
        return simple_stream_callback(conn, stream_id, user_data);
      },
    .end_stream =
      [](nghttp2_conn *conn, int64_t stream_id, void *user_data,
         void *stream_user_data) {
        return simple_stream_callback(conn, stream_id, user_data);
      },
    .recv_ping_ack =
      [](nghttp2_conn *conn, const nghttp2_ping_data *data, void *user_data) {
        return simple_callback(conn, user_data);
      },
    .shutdown =
      [](nghttp2_conn *conn, int64_t last_stream_id, uint32_t error_code,
         void *user_data) { return simple_callback(conn, user_data); },
  };

  nghttp2_settings settings;
  nghttp2_settings_default(&settings);
  settings.conn_id = fdp.ConsumeIntegral<uint64_t>();
  settings.settings_timeout = fdp.ConsumeIntegral<nghttp2_duration>();
  settings.hpack_max_dtable_capacity = fdp.ConsumeIntegral<size_t>();
  settings.hpack_encoder_max_dtable_capacity = fdp.ConsumeIntegral<size_t>();
  settings.max_concurrent_streams_local = fdp.ConsumeIntegral<uint32_t>();
  settings.max_concurrent_streams_remote = fdp.ConsumeIntegral<uint32_t>();
  settings.initial_max_stream_data = fdp.ConsumeIntegral<uint32_t>();
  settings.initial_max_data = fdp.ConsumeIntegral<uint32_t>();
  settings.enable_connect_protocol = fdp.ConsumeBool();
  settings.glitch_ratelim_burst = fdp.ConsumeIntegral<uint64_t>();
  settings.glitch_ratelim_rate = fdp.ConsumeIntegral<uint64_t>();

  nghttp2_conn *conn;
  int rv;

  auto server = fdp.ConsumeBool();
  if (server) {
    rv = nghttp2_conn_server_new(&conn, &callbacks, &settings, mem, &fdp);
  } else {
    rv = nghttp2_conn_client_new(&conn, &callbacks, &settings, mem, &fdp);
  }

  if (rv != 0) {
    return {};
  }

  return {conn, server};
}
} // namespace

namespace {
nghttp2_nv make_nv(const std::string_view &name,
                   const std::string_view &value) {
  return {
    .name = reinterpret_cast<uint8_t *>(const_cast<char *>(name.data())),
    .value = reinterpret_cast<uint8_t *>(const_cast<char *>(value.data())),
    .namelen = name.size(),
    .valuelen = value.size(),
  };
}
} // namespace

constexpr auto nulldata = std::array<uint8_t, 1 << 20>{};

namespace {
void run_test(nghttp2_conn *conn, FuzzedDataProvider &fdp) {
  static const auto reqnva = std::to_array({
    make_nv(":method"sv, "GET"sv),
    make_nv(":scheme"sv, "https"sv),
    make_nv(":authority"sv, "example.com"sv),
    make_nv(":path"sv, "/"sv),
  });
  static const auto resnva = std::to_array({
    make_nv(":status"sv, "200"sv),
    make_nv("server"sv, "nghttp2"sv),
  });
  static const auto infonva = std::to_array({
    make_nv(":status"sv, "103"sv),
    make_nv("link"sv, "url"sv),
  });
  static const auto trnva = std::to_array({
    make_nv("trailer1"sv, "value1"sv),
    make_nv("trailer2"sv, "value2"sv),
  });
  std::array<uint8_t, 16384> outbuf;

  auto dr = nghttp2_data_reader{
    .read_data = [](nghttp2_conn *conn, int64_t stream_id, nghttp2_vec *vec,
                    size_t veccnt, uint32_t *pflags, void *user_data,
                    void *stream_user_data) -> nghttp2_ssize {
      auto fdp = static_cast<FuzzedDataProvider *>(user_data);

      if (fdp->ConsumeBool()) {
        nghttp2_conn_shutdown_stream(conn, 0x00, stream_id,
                                     NGHTTP2_INTERNAL_ERROR);
      }

      if (fdp->ConsumeBool()) {
        nghttp2_conn_terminate(conn, NGHTTP2_NO_ERROR);
      }

      if (fdp->ConsumeBool()) {
        *pflags |= NGHTTP2_READ_DATA_FLAG_NO_END_STREAM;
      }

      veccnt = fdp->ConsumeIntegralInRange<size_t>(0, veccnt);

      for (auto i = 0UZ; i < veccnt; ++i) {
        vec[i] = nghttp2_vec{
          .base = const_cast<uint8_t *>(nulldata.data()),
          .len = fdp->ConsumeIntegralInRange<size_t>(0, nulldata.size()),
        };
      }

      if (veccnt == 0) {
        *pflags |= NGHTTP2_READ_DATA_FLAG_EOF;
      }

      return fdp->PickValueInArray<nghttp2_ssize>({
        static_cast<nghttp2_ssize>(veccnt),
        NGHTTP2_ERR_WOULDBLOCK,
        NGHTTP2_ERR_CALLBACK_FAILURE,
      });
    },
  };

  auto ts = nghttp2_tstamp{};

  for (; fdp.remaining_bytes();) {
    ts = fdp.ConsumeIntegralInRange<nghttp2_tstamp>(
      ts, std::numeric_limits<nghttp2_tstamp>::max() - 1);
    auto rawdata = fdp.ConsumeBytes<uint8_t>(
      fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes()));
    auto data = std::span{rawdata};

    if (nghttp2_conn_read(conn, data.data(), data.size(), ts) != 0) {
      return;
    }

    if (nghttp2_conn_is_server(conn)) {
      if (fdp.ConsumeBool()) {
        auto stream_id = static_cast<int64_t>(
          fdp.ConsumeIntegralInRange<int32_t>(0, INT32_MAX) | 0x1);

        for (; fdp.ConsumeBool();) {
          auto rv = nghttp2_conn_submit_info(conn, stream_id, infonva.data(),
                                             infonva.size());
          if (rv != 0) {
            if (nghttp2_err_is_fatal(rv)) {
              return;
            }

            break;
          }
        }

        auto rv = nghttp2_conn_submit_response(
          conn, stream_id, resnva.data(), resnva.size(),
          fdp.ConsumeBool() ? &dr : nullptr);
        if (nghttp2_err_is_fatal(rv)) {
          return;
        }

        if (fdp.ConsumeBool()) {
          auto rv = nghttp2_conn_submit_trailers(conn, stream_id, trnva.data(),
                                                 trnva.size());
          if (nghttp2_err_is_fatal(rv)) {
            return;
          }
        }
      }
    } else if (fdp.ConsumeBool()) {
      auto stream_id =
        nghttp2_conn_submit_request(conn, reqnva.data(), reqnva.size(),
                                    fdp.ConsumeBool() ? &dr : nullptr, NULL);
      if (stream_id < 0) {
        if (nghttp2_err_is_fatal(static_cast<int>(stream_id))) {
          return;
        }
      } else if (fdp.ConsumeBool()) {
        auto rv = nghttp2_conn_submit_trailers(conn, stream_id, trnva.data(),
                                               trnva.size());
        if (nghttp2_err_is_fatal(rv)) {
          return;
        }
      }
    }

    if (fdp.ConsumeBool()) {
      auto stream_id = static_cast<int64_t>(
        fdp.ConsumeIntegralInRange<int32_t>(0, INT32_MAX) | 0x1);

      nghttp2_conn_shutdown_stream(conn, 0x00, stream_id, NGHTTP2_NO_ERROR);
    }

    if (fdp.ConsumeBool()) {
      nghttp2_conn_terminate(conn, NGHTTP2_NO_ERROR);
    }

    auto outbuflen = fdp.ConsumeIntegralInRange<size_t>(9, outbuf.size());

    auto nwrite = nghttp2_conn_write(conn, outbuf.data(), outbuflen, ts);
    if (nwrite < 0) {
      return;
    }
  }
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  auto fdp = FuzzedDataProvider{data, size};
  const auto mem = setup_mem(fdp);

  auto [conn, server] = setup_conn(fdp, &mem);
  if (!conn) {
    return 0;
  }

  run_test(conn, fdp);

  nghttp2_conn_del(conn);

  return 0;
}
