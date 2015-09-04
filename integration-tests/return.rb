Nghttpx.run do |env|
  resp = env.resp

  resp.clear_headers
  resp.status = 404
  resp.add_header "from", "mruby"
  resp.return "Hello World"
end
