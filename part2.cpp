#include <iostream>

#include <openssl/ssl.h>
#include <openssl/bio.h>



int main(int argv, char *argc[]) {

  File * rsa_prk = fopen("rsaprivatekey.pem");
  //rsa_prk = PEM_read_bio_RSAPrivateKey( );

 
  return 0;
}
