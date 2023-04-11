#include "common.h"
#include "SSLClient.h"

namespace ssl
{
  SSL_CTX* client::globalSSLContext_ = nullptr;

  client::client(int afd, mode mode, std::string hostName)
  {
    fd_ = afd;

    readBIO_ = BIO_new(BIO_s_mem());
    writeBIO_ = BIO_new(BIO_s_mem());
    localSSLContext_  = SSL_new(cmn::SSLContext::get());

    if (mode == mode::server)
      SSL_set_accept_state(localSSLContext_);  /* localSSLContext_ server mode */
    else if (mode == mode::client)
      SSL_set_connect_state(localSSLContext_); /* localSSLContext_ client mode */

    SSL_set_bio(localSSLContext_, readBIO_, writeBIO_);

    onReadCallback_ = cmn::PrintUnencryptedData;

    if (false == hostName.empty())
      SSL_set_tlsext_host_name(localSSLContext_, hostName.c_str()); // TLS SNI
  }

  client::~client()
  {
    SSL_free(localSSLContext_);   /* free the SSL object and its BIO's */

    free(writeBuffer_);
    free(encryptBuffer_);
  }

  int client::wannaWrite() const
  {
    return (writeBufferLength_ > 0);
  }

  client::status client::getSSLStatus(int n) const
  {
    switch (SSL_get_error(localSSLContext_, n))
    {
      case SSL_ERROR_NONE:
        return status::ok;

      case SSL_ERROR_WANT_WRITE:
      case SSL_ERROR_WANT_READ:
        return status::want_io;

      case SSL_ERROR_ZERO_RETURN:
      case SSL_ERROR_SYSCALL:
      default:
        return status::fail;
    }
  }

  void client::sendUnencryptedBytes(const char *buf, size_t len)
  {
    encryptBuffer_ = static_cast<char*>(realloc(encryptBuffer_, encryptBufferLength_ + len));
    memcpy(encryptBuffer_ + encryptBufferLength_, buf, len);
    encryptBufferLength_ += len;
  }

  void client::queueEncryptedBytes(const char *buf, size_t len)
  {
    writeBuffer_ = static_cast<char*>(realloc(writeBuffer_, writeBufferLength_ + len));
    memcpy(writeBuffer_ + writeBufferLength_, buf, len);
    writeBufferLength_ += len;
  }

  void client::printSSLState()
  {
    const char * current_state = SSL_state_string_long(localSSLContext_);
    if (current_state != lastState_) 
    {
      if (current_state)
        printf("SSL-STATE: %s\n", current_state);

      lastState_ = current_state;
    }
  }

  client::status client::doSSLHandshake()
  {
    char buf[DEFAULT_BUF_SIZE] = {0};

    printSSLState();
    int n = SSL_do_handshake(localSSLContext_);
    printSSLState();

    const status status = getSSLStatus(n);

    /* Did SSL request to write bytes? */
    if (status == status::want_io)
      do {
        n = BIO_read(writeBIO_, buf, sizeof(buf));
        if (n > 0)
          queueEncryptedBytes(buf, n);
        else if (!BIO_should_retry(writeBIO_))
          return status::fail;
      } while (n > 0);

    return status;
  }

  int client::onReadCallback(char* src, size_t len)
  {
    while (len > 0) 
    {
      int n = BIO_write(readBIO_, src, len);

      if (n <= 0)
        return -1; /* assume bio write failure is unrecoverable */

      src += n;
      len -= n;

      if (!SSL_is_init_finished(localSSLContext_)) {
        if (doSSLHandshake() == status::fail)
          return -1;
        if (!SSL_is_init_finished(localSSLContext_))
          return 0;
      }

      char buf[DEFAULT_BUF_SIZE] = {0};

      /* The encrypted data is now in the input bio so now we can perform actual
       * read of unencrypted data. */
      do 
      {
        n = SSL_read(localSSLContext_, buf, sizeof(buf));
        if (n > 0)
          onReadCallback_(buf, static_cast<size_t>(n));
      } while (n > 0);

      const status status = getSSLStatus(n);

      /* Did SSL request to write bytes? This can happen if peer has requested SSL
       * renegotiation. */
      if (status == status::want_io)
      {
        do 
        {
          n = BIO_read(writeBIO_, buf, sizeof(buf));
          if (n > 0)
            queueEncryptedBytes(buf, n);
          else if (!BIO_should_retry(writeBIO_))
            return -1;
        } while (n>0);
      }

      if (status == status::fail)
        return -1;
    }

    return 0;
  }

  int client::doEncrypt()
  {
    if (!SSL_is_init_finished(localSSLContext_))
      return 0;

    while (encryptBufferLength_>0) {
      int n = SSL_write(localSSLContext_, encryptBuffer_, encryptBufferLength_);
      const status status = getSSLStatus(n);

      if (n>0) {
        /* consume the waiting bytes that have been used by SSL */
        if (static_cast<size_t>(n) < encryptBufferLength_)
          memmove(encryptBuffer_, encryptBuffer_ + n, encryptBufferLength_ - n);
        encryptBufferLength_ -= n;
        encryptBuffer_ = static_cast<char*>(realloc(encryptBuffer_, encryptBufferLength_));

        char buf[DEFAULT_BUF_SIZE] = {0};

        /* take the output of the SSL object and queue it for socket write */
        do {
          n = BIO_read(writeBIO_, buf, sizeof(buf));
          if (n > 0)
            queueEncryptedBytes(buf, n);
          else if (!BIO_should_retry(writeBIO_))
            return -1;
        } while (n>0);
      }

      if (status == status::fail)
        return -1;

      if (n==0)
        break;
    }
    return 0;
  }

  void client::doStdInRead()
  {
    char buf[DEFAULT_BUF_SIZE] = {0};
    const size_t n = _read(STDIN_FILENO, buf, sizeof(buf));
    if (n > 0)
      sendUnencryptedBytes(buf, n);
  }

  int client::doSockRead()
  {
    char buf[DEFAULT_BUF_SIZE];
    const size_t n = _read(fd_, buf, sizeof(buf));

    if (n > 0)
      return onReadCallback(buf, n);

    return -1;
  }

  int client::doSockWrite()
  {
    size_t n = _write(fd_, writeBuffer_, writeBufferLength_);
    if (n > 0) 
    {
      if (n < writeBufferLength_)
        memmove(writeBuffer_, writeBuffer_+n, writeBufferLength_-n);

      writeBufferLength_ -= n;
      writeBuffer_ = static_cast<char*>(realloc(writeBuffer_, writeBufferLength_));

      return 0;
    }

    return -1;
  }

  bool client::doHaveDataToEncrypt() const
  {
    return (encryptBufferLength_ > 0);
  }
}