Nghttpx.run do |resp, req|
  resp.clear_headers
  resp.status = 404
  resp.add_header "from", "mruby"
  resp.return "Hello World"
end
