#!/bin/sh

key="server.key"
csr="server.csr"
cert="server.crt"
conf="ssl.conf"

rm -f $key $csr $cert

echo "----------genrsa----------"
openssl genrsa -out $key 2048

echo "----------req-------------"
openssl req -new -sha256 -out $csr -key $key -config $conf
#debug
openssl req -text -noout -in $csr

echo "----------x509------------"
openssl x509 -req -days 3650 -in $csr -signkey $key -out $cert -extensions req_ext -extfile $conf

echo "ok!"
