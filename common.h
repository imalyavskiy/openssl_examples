/*
  Copyright (c) 2017 Darren Smith

  ssl_examples is free software; you can redistribute it and/or modify
  it under the terms of the MIT license. See LICENSE for details.
*/
#ifndef __COMMON_H__
#define __COMMON_H__

#include <cstdint>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <io.h>
#include <WinSock2.h>
#include <Ws2ipdef.h>
#include <WS2tcpip.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <sys/types.h>

#define STDIN_FILENO 0

#define DEFAULT_BUF_SIZE 64

#define int_error(msg) HandleError(__FILE__, __LINE__, msg)
namespace cmn
{
void HandleError(const char *file, int lineNo, const char *msg);

void Die(const char *msg);

void PrintUnencryptedData(char *buf, size_t len);

void PrintSSLError();

struct SSLContext
{
  static SSL_CTX* get();

  /**
   * \brief Initialzes global SSL context. Must be called before any OpenSSL operations.
   * \param certificateFile path to a file containing server certificate
   * \param keyFile path to a file containing server private key
   * \remark both parameters can be empty in order to init SSL for client side.
   */
  static void init(const std::string& certificateFile = {}, const std::string& keyFile = {});

private:
    /* Global SSL context */
  static SSL_CTX* sslContext_;
};

// Basic configuration data
struct Config
{
  // port name
  int port;

  // remote host IP address. Attention! This must be a numeric address, not a
  // server host name, because this example code does not perform address lookup.
  std::string hostIP;

  // provide the hostname if this SSL client needs to use SNI to tell the server
  // what certificate to use
  std::string hostName;

  // socket family, AF_INET (ipv4) or AF_INET6 (ipv6), must match host_ip above
  int ipFamily;
};

Config Configure(int argc, char **argv);
}
#endif // __COMMON_H__