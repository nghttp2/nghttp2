Nghttpx.run do |resp, req|
  resp.set_header "Alpha", "bravo"
end
