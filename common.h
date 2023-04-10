/*
  Copyright (c) 2017 Darren Smith

  ssl_examples is free software; you can redistribute it and/or modify
  it under the terms of the MIT license. See LICENSE for details.
*/

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <WinSock2.h>
#include <Ws2ipdef.h>
#include <WS2tcpip.h>
#include <io.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>

#define STDIN_FILENO 0

/* Global SSL context */
SSL_CTX *g_SSLContext = nullptr;

#define DEFAULT_BUF_SIZE 64

void HandleError(const char *file, int lineno, const char *msg) {
  fprintf(stderr, "** %s:%i %s\n", file, lineno, msg);
  ERR_print_errors_fp(stderr);
  exit(-1);
}

#define int_error(msg) HandleError(__FILE__, __LINE__, msg)

void Die(const char *msg) {
  perror(msg);
  exit(1);
}

void PrintUnencryptedData(char *buf, size_t len) {
  printf("%.*s", (int)len, buf);
}

/* An instance of this object is created each time a client connection is
 * accepted. It stores the client file descriptor, the SSL objects, and data
 * which is waiting to be either written to socket or encrypted. */
struct SSLClient
{
  int fd;

  SSL *ssl;

  BIO *rbio; /* SSL reads from, we write to. */
  BIO *wbio; /* SSL writes to, we read from. */

  /* Bytes waiting to be written to socket. This is data that has been generated
   * by the SSL object, either due to encryption of user input, or, writes
   * requires due to peer-requested SSL renegotiation. */
  char* write_buf;
  size_t write_len;

  /* Bytes waiting to be encrypted by the SSL object. */
  char* encrypt_buf;
  size_t encrypt_len;

  /* Store the previous state string */
  const char * last_state;

  /* Method to invoke when unencrypted bytes are available. */
  void (*io_on_read)(char *buf, size_t len);
} sslClient;

/* This enum contols whether the SSL connection needs to initiate the SSL
 * handshake. */
enum ssl_mode { SSLMODE_SERVER, SSLMODE_CLIENT };


void SSLClientInit(SSLClient *sslClient, int fd, enum ssl_mode mode)
{
  memset(sslClient, 0, sizeof(SSLClient));

  sslClient->fd = fd;

  sslClient->rbio = BIO_new(BIO_s_mem());
  sslClient->wbio = BIO_new(BIO_s_mem());
  sslClient->ssl = SSL_new(g_SSLContext);

  if (mode == SSLMODE_SERVER)
    SSL_set_accept_state(sslClient->ssl);  /* ssl server mode */
  else if (mode == SSLMODE_CLIENT)
    SSL_set_connect_state(sslClient->ssl); /* ssl client mode */

  SSL_set_bio(sslClient->ssl, sslClient->rbio, sslClient->wbio);

  sslClient->io_on_read = PrintUnencryptedData;
}


void SSLClientCleanup(SSLClient *sslClient)
{
  SSL_free(sslClient->ssl);   /* free the SSL object and its BIO's */
  free(sslClient->write_buf);
  free(sslClient->encrypt_buf);
}


int SSLClientWantWrite(SSLClient *cp) {
  return (cp->write_len>0);
}


/* Obtain the return value of an SSL operation and convert into a simplified
 * error code, which is easier to examine for failure. */
enum sslstatus { SSLSTATUS_OK, SSLSTATUS_WANT_IO, SSLSTATUS_FAIL};


static enum sslstatus GetSSLStatus(SSL* ssl, int n)
{
  switch (SSL_get_error(ssl, n))
  {
    case SSL_ERROR_NONE:
      return SSLSTATUS_OK;
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_READ:
      return SSLSTATUS_WANT_IO;
    case SSL_ERROR_ZERO_RETURN:
    case SSL_ERROR_SYSCALL:
    default:
      return SSLSTATUS_FAIL;
  }
}


/* Handle request to send unencrypted data to the SSL.  All we do here is just
 * queue the data into the encrypt_buf for later processing by the SSL
 * object. */
void SendUnencryptedBytes(const char *buf, size_t len)
{
  sslClient.encrypt_buf = (char*)realloc(sslClient.encrypt_buf, sslClient.encrypt_len + len);
  memcpy(sslClient.encrypt_buf + sslClient.encrypt_len, buf, len);
  sslClient.encrypt_len += len;
}


/* Queue encrypted bytes. Should only be used when the SSL object has requested a
 * write operation. */
void QueueEncryptedBytes(const char *buf, size_t len)
{
  sslClient.write_buf = (char*)realloc(sslClient.write_buf, sslClient.write_len + len);
  memcpy(sslClient.write_buf + sslClient.write_len, buf, len);
  sslClient.write_len += len;
}


void PrintSSLState()
{
  const char * current_state = SSL_state_string_long(sslClient.ssl);
  if (current_state != sslClient.last_state) {
    if (current_state)
      printf("SSL-STATE: %s\n", current_state);
    sslClient.last_state = current_state;
  }
}


void PrintSSLError()
{
  BIO *bio = BIO_new(BIO_s_mem());
  ERR_print_errors(bio);
  char *buf;
  size_t len = BIO_get_mem_data(bio, &buf);
  if (len > 0)
    printf("SSL-ERROR: %s", buf);
  BIO_free(bio);
}


enum sslstatus DoSSLHandshake()
{
  char buf[DEFAULT_BUF_SIZE];
  enum sslstatus status;

  PrintSSLState();
  int n = SSL_do_handshake(sslClient.ssl);
  PrintSSLState();
  status = GetSSLStatus(sslClient.ssl, n);

  /* Did SSL request to write bytes? */
  if (status == SSLSTATUS_WANT_IO)
    do {
      n = BIO_read(sslClient.wbio, buf, sizeof(buf));
      if (n > 0)
        QueueEncryptedBytes(buf, n);
      else if (!BIO_should_retry(sslClient.wbio))
        return SSLSTATUS_FAIL;
    } while (n>0);

  return status;
}

/* Process SSL bytes received from the peer. The data needs to be fed into the
   SSL object to be unencrypted.  On success, returns 0, on SSL error -1. */
int OnReadCallback(char* src, size_t len)
{
  char buf[DEFAULT_BUF_SIZE];
  enum sslstatus status;
  int n;

  while (len > 0) {
    n = BIO_write(sslClient.rbio, src, len);

    if (n<=0)
      return -1; /* assume bio write failure is unrecoverable */

    src += n;
    len -= n;

    if (!SSL_is_init_finished(sslClient.ssl)) {
      if (DoSSLHandshake() == SSLSTATUS_FAIL)
        return -1;
      if (!SSL_is_init_finished(sslClient.ssl))
        return 0;
    }

    /* The encrypted data is now in the input bio so now we can perform actual
     * read of unencrypted data. */

    do {
      n = SSL_read(sslClient.ssl, buf, sizeof(buf));
      if (n > 0)
        sslClient.io_on_read(buf, (size_t)n);
    } while (n > 0);

    status = GetSSLStatus(sslClient.ssl, n);

    /* Did SSL request to write bytes? This can happen if peer has requested SSL
     * renegotiation. */
    if (status == SSLSTATUS_WANT_IO)
      do {
        n = BIO_read(sslClient.wbio, buf, sizeof(buf));
        if (n > 0)
          QueueEncryptedBytes(buf, n);
        else if (!BIO_should_retry(sslClient.wbio))
          return -1;
      } while (n>0);

    if (status == SSLSTATUS_FAIL)
      return -1;
  }

  return 0;
}

/* Process outbound unencrypted data that is waiting to be encrypted.  The
 * waiting data resides in encrypt_buf.  It needs to be passed into the SSL
 * object for encryption, which in turn generates the encrypted bytes that then
 * will be queued for later socket write. */
int DoEncrypt()
{
  char buf[DEFAULT_BUF_SIZE];
  enum sslstatus status;

  if (!SSL_is_init_finished(sslClient.ssl))
    return 0;

  while (sslClient.encrypt_len>0) {
    int n = SSL_write(sslClient.ssl, sslClient.encrypt_buf, sslClient.encrypt_len);
    status = GetSSLStatus(sslClient.ssl, n);

    if (n>0) {
      /* consume the waiting bytes that have been used by SSL */
      if ((size_t)n<sslClient.encrypt_len)
        memmove(sslClient.encrypt_buf, sslClient.encrypt_buf+n, sslClient.encrypt_len-n);
      sslClient.encrypt_len -= n;
      sslClient.encrypt_buf = (char*)realloc(sslClient.encrypt_buf, sslClient.encrypt_len);

      /* take the output of the SSL object and queue it for socket write */
      do {
        n = BIO_read(sslClient.wbio, buf, sizeof(buf));
        if (n > 0)
          QueueEncryptedBytes(buf, n);
        else if (!BIO_should_retry(sslClient.wbio))
          return -1;
      } while (n>0);
    }

    if (status == SSLSTATUS_FAIL)
      return -1;

    if (n==0)
      break;
  }
  return 0;
}


/* Read bytes from stdin and queue for later encryption. */
void DoStdinRead()
{
  char buf[DEFAULT_BUF_SIZE];
  size_t n = _read(STDIN_FILENO, buf, sizeof(buf));
  if (n>0)
    SendUnencryptedBytes(buf, (size_t)n);
}


/* Read encrypted bytes from socket. */
int DoSockRead()
{
  char buf[DEFAULT_BUF_SIZE];
  size_t n = _read(sslClient.fd, buf, sizeof(buf));

  if (n>0)
    return OnReadCallback(buf, (size_t)n);
  else
    return -1;
}


/* Write encrypted bytes to the socket. */
int DoSockWrite()
{
  size_t n = _write(sslClient.fd, sslClient.write_buf, sslClient.write_len);
  if (n>0) {
    if ((size_t)n < sslClient.write_len)
      memmove(sslClient.write_buf, sslClient.write_buf+n, sslClient.write_len-n);
    sslClient.write_len -= n;
    sslClient.write_buf = (char*)realloc(sslClient.write_buf, sslClient.write_len);
    return 0;
  }
  else
    return -1;
}


void SSLInit(const char * certfile, const char* keyfile)
{
  /* SSL library initialisation */

  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
#if OPENSSL_VERSION_MAJOR < 3
  ERR_load_BIO_strings(); // deprecated since OpenSSL 3.0
#endif
  ERR_load_crypto_strings();

  /* create the SSL server context */
  g_SSLContext = SSL_CTX_new(TLS_method());
  if (!g_SSLContext)
    Die("SSL_CTX_new()");

  /* Load certificate and private key files, and check consistency */
  if (certfile && keyfile) {
    if (SSL_CTX_use_certificate_file(g_SSLContext, certfile,  SSL_FILETYPE_PEM) != 1)
      int_error("SSL_CTX_use_certificate_file failed");

    if (SSL_CTX_use_PrivateKey_file(g_SSLContext, keyfile, SSL_FILETYPE_PEM) != 1)
      int_error("SSL_CTX_use_PrivateKey_file failed");

    /* Make sure the key and certificate file match. */
    if (SSL_CTX_check_private_key(g_SSLContext) != 1)
      int_error("SSL_CTX_check_private_key failed");
    else
      printf("certificate and private key loaded and verified\n");
  }


  /* Recommended to avoid SSLv2 & SSLv3 */
  SSL_CTX_set_options(g_SSLContext, SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);
}

