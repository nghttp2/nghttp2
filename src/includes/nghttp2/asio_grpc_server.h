/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2022 Nils Carlson
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
#ifndef NGHTTP2_ASIO_GRPC_SERVER_H
#define NGHTTP2_ASIO_GRPC_SERVER_H

#include <nghttp2/asio_http2_server.h>
#include <iostream>

namespace nghttp2 {

namespace asio_grpc {

namespace server {

extern "C" {
struct __attribute__((packed)) grpc_header {
    uint8_t flags;
    uint32_t length;
};
}

template< typename T, typename U> class grpc_unary_request;
template< typename U> class grpc_unary_response;

template<typename T, typename U> using on_unary_grpc = std::function< void(const grpc_unary_request< T, U > &&, grpc_unary_response< U > &&) >;

class grpc_unary_request_impl
{


};

template< typename T, typename U> class grpc_unary_request
{
public:
    grpc_unary_request( const on_unary_grpc< T, U> &on_unary_grpc,
                        const ::nghttp2::asio_http2::server::request &request ) :
        on_unary_grpc_{ on_unary_grpc },
        request_{ request }
    {
    }

    void receive_message( grpc_unary_request< T, U > &&grpc_unary_request,
                          grpc_unary_response< U > &&grpc_unary_response )
    {
        grpc_header header = { 0, 0 };
        std::string buffer;
        bool have_header = false;

        grpc_unary_request.request_.on_data([header, buffer, have_header,
                                            grpc_unary_request = std::move(grpc_unary_request),
                                            grpc_unary_response = std::move(grpc_unary_response)] (const uint8_t *data, std::size_t len) mutable
        {
            if (len == 0)
            {
                return;
            }

            std::copy_n(data, len, std::back_inserter(buffer));

            if (!have_header && buffer.size() >= sizeof (header))
            {
                memcpy(&header, buffer.data(), sizeof (header));
                header.length = ntohl(header.length);
                have_header = true;
            }

            if (have_header && buffer.size() >= (header.length + sizeof (header) ))
            {
                auto parsed = grpc_unary_request.get_message().ParseFromArray( buffer.data() + sizeof (header), header.length );
                if (!parsed)
                {
                    // error!
                }
                buffer.erase(0, sizeof(header));
                have_header = false;

                if (parsed)
                {
                    grpc_unary_request.on_unary_grpc_( std::move( grpc_unary_request ), std::move( grpc_unary_response ) );
                }

            }
        });
    }

    T &get_message()
    {
        return message_;
    }

    const T &get_message() const
    {
        return message_;
    }

private:
    T message_;
    on_unary_grpc< T, U> on_unary_grpc_;
    const ::nghttp2::asio_http2::server::request &request_;
};


template< typename U> class grpc_unary_response
{
public:
    grpc_unary_response( const ::nghttp2::asio_http2::server::response &response ) :
        response_{ response }
    {}

    void write_response( )
    {
        ::nghttp2::asio_http2::header_map grpc_response_header;
        ::nghttp2::asio_http2::header_value grpc_status_value = { "0", 0 };
        grpc_response_header.insert({ "content-type", {"application/grpc", 0} });
        response_.write_head(200, grpc_response_header);

        auto encoded = message_.SerializeAsString();
        if (encoded.empty())
        {
            std::cerr << "Encoding gailed\n";
            // error!
        }

        std::vector<char> buf;
        buf.resize(sizeof (grpc_header) + encoded.size() );
        std::cerr << "buf size: " << buf.size() << "\n";

        grpc_header *header = reinterpret_cast<grpc_header *>(buf.data());

        header->flags = 0;
        header->length = htonl( encoded.size() );

        std::copy_n(encoded.data(), encoded.size(), buf.data() + sizeof(grpc_header ));

        std::cerr << "message size: " << ntohl(reinterpret_cast<const grpc_header *>(buf.data())->length) << "\n";

        std::size_t count = 0;
        response_.end([=](uint8_t *data, std::size_t len, uint32_t *data_flags) mutable {


            *data_flags |= NGHTTP2_DATA_FLAG_EOF | NGHTTP2_DATA_FLAG_NO_END_STREAM;

            std::cerr << "len " << len << " bytes\n";
            std::cerr << "count " << count << " bytes\n";

            std::size_t to_copy = std::min(buf.size() - count, len );
            std::copy_n( buf.data() + count, to_copy, data );
            std::cerr << "Copied " << to_copy << " bytes\n";

            count += to_copy;

            if (count == buf.size())
            {
                ::nghttp2::asio_http2::header_map grpc_response_trailer;
                grpc_response_trailer.insert({ "grpc-status", {"0", 0} });
                response_.write_trailer(grpc_response_trailer);

                std::cerr << "Wrote all data!\n";
            }
            return to_copy;
        });

    }

    U &getMessage()
    {
        return message_;
    }

private:
    U message_;
    const ::nghttp2::asio_http2::server::response &response_;
};


template<typename T, typename U>
class grpc_unary_handler
{
public:

    grpc_unary_handler(on_unary_grpc<T,U> &&on_request ) :
        on_request_{on_request}
    {
    }

    void operator()( const ::nghttp2::asio_http2::server::request &req, const ::nghttp2::asio_http2::server::response &res ) const
    {
        grpc_unary_request<T,U> request{ on_request_, req };
        grpc_unary_response<U> response{ res };

        request.receive_message(std::move(request), std::move(response));
    }

private:
    on_unary_grpc< T, U > on_request_;
};

} // namespace client

} // namespace asio_grpc

} // namespace nghttp2

#endif // NGHTTP2_ASIO_HTTP2_CLIENT_H
