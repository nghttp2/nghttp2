fetch-ocsp-response is a Perl script to perform OCSP query and get
response.  It uses openssl command under the hood.  nghttpx uses it to
enable OCSP stapling feature.

fetch-ocsp-response has been developed as part of h2o project
(https://github.com/h2o/h2o).  The script file with the same name in
this directory was copied from their github repository.

fetch-ocsp-response is usually installed under $(pkgdatadir), which is
$(prefix)/share/nghttp2.
