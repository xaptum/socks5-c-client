# socks5-c-client
Example SOCKS5 client for use with the Xaptum ENF

# Introduction

This project is a toy example of a TCP client
that connects to the Xaptum ENF SOCKS5 proxy,
to establish a TCP connection with a server on the ENF.

The SOCKS5 protocol is documented in [RFC1928](https://tools.ietf.org/html/rfc1928).

The SOCKS5 client code is contained in the files
`include/xsocks/socks5.h` and `src/socks5.c`.
These files provide a `xsocks_socks5_connect` function
that implements the client-side of the SOCKS5 `connect` negotiation.

Basic TCP and TLS connection code is also provided in the `tcp` and `tls` files.

# DISCLAIMER

This code is provided for *demonstration purposes only*.

The security and correctness of the code has not been fully audited.
It should not be used in a production environment.

# Building

## Dependencies

* CMake (version 3.12 or higher)
* A C99-compliant compiler

* OpenSSL (version 1.1.0 or higher)

## Building the Executable

This project has only been tested on Linux.

```bash
# Create the out-of-source build tree
mkdir -p build
cd build

# Configure the build
cmake ..

# Build
cmake --build .
```

This results in an executable `socks5_c_client` in the `build` directory.

# Usage

The compiled executable includes a help message
describing the necessary parameters:
```bash
socks5_c_client -h
```

This example client takes as parameters:
- Client's TLS certificate for connecting to the ENF
- Client's TLS private key for connecting to the ENF
- Xaptum root TLS certificate
- Xaptum IPv6 of the TCP server you wish to contact
- TCP port of the server you wish to contact

The example client simply makes the connection
to the given server, and sends the static message "hi!".

# License
Copyright 2021 Xaptum, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not
use this work except in compliance with the License. You may obtain a copy of
the License from the LICENSE.txt file or at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations under
the License.
