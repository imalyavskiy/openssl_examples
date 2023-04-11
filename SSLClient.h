#ifndef __SSL_CLIENT_H__
#define __SSL_CLIENT_H__
#pragma once

#include "common.h"
namespace ssl
{
  /* An instance of this object is created each time a client connection is
   * accepted. It stores the client file descriptor, the SSL objects, and data
   * which is waiting to be either written to socket or encrypted. */
  class client
  {
  public:
    client(const client&) = delete;
    client(client&&) = delete;
    client& operator=(const client&) = delete;
    client& operator=(client&&) = delete;

    /* Obtain the return value of an SSL operation and convert into a simplified
     * error code, which is easier to examine for failure. */
    enum class status { ok, want_io, fail};

    /* This enum contols whether the SSL connection needs to initiate the SSL
     * handshake. */
    enum class mode { server, client };

    static SSL_CTX* context();

    client(int afd, mode mode, std::string hostName = {});

    ~client();

    /* Read bytes from stdin and queue for later encryption. */
    void doStdInRead();

    /**/
    status doSSLHandshake();

    /**/
    int wannaWrite() const;

    /**/
    void printSSLState();

    /* Read encrypted bytes from socket. */
    int doSockRead();

    /* Process outbound unencrypted data that is waiting to be encrypted.  The
     * waiting data resides in encryptBuffer_.  It needs to be passed into the SSL
     * object for encryption, which in turn generates the encrypted bytes that then
     * will be queued for later socket write. */
    int doEncrypt();

    /* Write encrypted bytes to the socket. */
    int doSockWrite();

    bool doHaveDataToEncrypt() const;

  protected:
    /* Handle request to send unencrypted data to the SSL.  All we do here is just
     * queue the data into the encryptBuffer_ for later processing by the SSL
     * object. */
    void sendUnencryptedBytes(const char *buf, size_t len);

    /**/
    status getSSLStatus(int n) const;

    /* Queue encrypted bytes. Should only be used when the SSL object has requested a
     * write operation. */
    void queueEncryptedBytes(const char *buf, size_t len);

    /* Process SSL bytes received from the peer. The data needs to be fed into the
     * SSL object to be unencrypted.  On success, returns 0, on SSL error -1. */
    int onReadCallback(char* src, size_t len);

  protected:

    static SSL_CTX* globalSSLContext_;

    int fd_ = 0;

    SSL* localSSLContext_ = nullptr;

    BIO* readBIO_ = nullptr; /* SSL reads from, we write to. */
    BIO* writeBIO_ = nullptr; /* SSL writes to, we read from. */

    /* Bytes waiting to be written to socket. This is data that has been generated
     * by the SSL object, either due to encryption of user input, or, writes
     * requires due to peer-requested SSL renegotiation. */
    char* writeBuffer_ = nullptr;
    size_t writeBufferLength_ = 0;

    /* Bytes waiting to be encrypted by the SSL object. */
    char* encryptBuffer_ = nullptr;
    size_t encryptBufferLength_ = 0;

    /* Store the previous state string */
    const char* lastState_ = nullptr;

    /* Method to invoke when unencrypted bytes are available. */
    void (*onReadCallback_)(char *buf, size_t len) = nullptr;
  };
}
#endif // __SSL_CLIENT_H__
