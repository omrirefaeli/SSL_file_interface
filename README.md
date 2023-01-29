# SSL_file_interface
An assignment as part of a BS.c in Computer Science. A client &amp; server interface, over SSL

Based on the guidelines of [this task](http://gcmuganda.faculty.noctrl.edu/classes/Spring13/479/SSLHomework3.htm)

x509 certificate files were created using the command
`openssl req -new -newkey rsa:2048 -nodes -keyout privateKey.key -out server.crt -x509 -days 365 -subj "/C=US/ST=CA/L=San Francisco/O=My Organization/CN=localhost"`

## How to run

### server

run `python server.py`

### client

run `python client.py`
