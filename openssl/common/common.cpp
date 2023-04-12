#include "common.h"
namespace cmn
{
  void HandleError(const char *file, int lineNo, const char *msg) {
    fprintf(stderr, "** %s:%i %s\n", file, lineNo, msg);
    ERR_print_errors_fp(stderr);
    exit(-1);
  }

  void Die(const char *msg) {
    perror(msg);
    exit(1);
  }

  void PrintUnencryptedData(char *buf, size_t len) {
    printf("%.*s", (int)len, buf);
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

  SSL_CTX* SSLContext::sslContext_ = nullptr;

  SSL_CTX* SSLContext::get()
  {
    if(nullptr == sslContext_)
      Die("No SSL Context");

    return sslContext_;
  }

  void SSLContext::init(const std::string& certificateFile, const std::string& keyFile)
  {
    /* SSL library initialization */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
  #if OPENSSL_VERSION_MAJOR < 3
    ERR_load_BIO_strings(); // deprecated since OpenSSL 3.0
  #endif
    ERR_load_crypto_strings();

    /* create the SSL server context */
    sslContext_ = SSL_CTX_new(TLS_method());
    if (!sslContext_)
      Die("SSL_CTX_new()");

    /* Load certificate and private key files, and check consistency */
    if (false == certificateFile.empty() && false == keyFile.empty()) {
      if (SSL_CTX_use_certificate_file(sslContext_, certificateFile.c_str(),  SSL_FILETYPE_PEM) != 1)
        int_error("SSL_CTX_use_certificate_file failed");

      if (SSL_CTX_use_PrivateKey_file(sslContext_, keyFile.c_str(), SSL_FILETYPE_PEM) != 1)
        int_error("SSL_CTX_use_PrivateKey_file failed");

      /* Make sure the key and certificate file match. */
      if (SSL_CTX_check_private_key(sslContext_) != 1)
        int_error("SSL_CTX_check_private_key failed");
      else
        printf("certificate and private key loaded and verified\n");
    }

    /* Recommended to avoid SSLv2 & SSLv3 */
    SSL_CTX_set_options(sslContext_, SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);
  }

  Config Configure(int argc, char** argv)
  {
    return Config{
      argc > 1 ? atoi(argv[1]) : 55555,
      "127.0.0.1",
      "api.huobi.pro",
      AF_INET,
    };
  }
}
