#include "openssl/include/openssl/evp.h"
#include "openssl/include/openssl/ssl.h"

void ____dont_use_this_function_unused_padding_for_build____(void)
{
    const EVP_MD *md;
    SSL_CTX *sslctx;

    md = EVP_get_digestbyname("sm3");
    sslctx = SSL_CTX_new(TLS_method());

    (void)md;
    (void)sslctx;

    return;
}
