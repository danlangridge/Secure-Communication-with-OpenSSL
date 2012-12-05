#include <iostream>


#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>



using namespace std;

int main(int argc, char *argv[])
{
  SSL_library_init(); 
  //ERR_load_crypto_strings();
  SSL_load_error_strings();
	
  //This section uses BIOs to write a copy of infile.txt to outfile.txt
	//  and to send the hash of infile.txt to the command window.
	//  It is a barebones implementation with little to no error checking.

	//The SHA1 hash BIO is chained to the input BIO, though it could just
	//  as easily be chained to the output BIO instead.

  //plaintext files
  char infilename[] = "langridge.txt";
	char outfilename[] = "outfile.txt";
	
  //Buffers
  char* buffer[1024] = {0};
  char* encbuffer[1024] = {0};
  char* decbuffer[1024] = {0};

  BIO *binfile, *boutfile, *hash;
	
  binfile = BIO_new_file(infilename, "r");
	boutfile = BIO_new_file(outfilename, "w") ;
	
  hash = BIO_new(BIO_f_md());
	BIO_set_md(hash, EVP_sha1());

  BIO *bio_private_key = BIO_new_file("rsaprivatekey.pem", "r");
  RSA *rsa = PEM_read_bio_RSAPrivateKey(bio_private_key, NULL,NULL,NULL);
 
  BIO_read(binfile, buffer, 1024);

  RSA_private_encrypt( 1024, 
                       (unsigned char*)buffer, 
                       (unsigned char*)encbuffer, 
                       rsa, RSA_PKCS1_PADDING
                     );

  BIO *bio_public_key = BIO_new_file("rsapublickey.pem", "r");
  RSA *rsa_dec = PEM_read_bio_RSA_PUBKEY(bio_public_key, NULL, NULL, NULL);
  
  RSA_public_decrypt( 1024, 
                      (unsigned char*)encbuffer, 
                      (unsigned char*)decbuffer,
                      rsa_dec, RSA_PKCS1_PADDING
                    );

  //Chain on the input
	BIO_push(hash, binfile);

	//Chain on the output
	//BIO_push(hash, boutfile);

	int actualRead, actualWritten;

	while((actualRead = BIO_read(hash, decbuffer, 1024)) >= 1)
	{
		//Could send this to multiple chains from here
		actualWritten = BIO_write(boutfile, decbuffer, actualRead);
	}

	//Get digest
	char mdbuf[EVP_MAX_MD_SIZE];
	int mdlen = BIO_gets(hash, mdbuf, EVP_MAX_MD_SIZE);
	for(int i = 0; i < mdlen; i++)
	{
		//Print two hexadecimal digits (8 bits or 1 character) at a time
		printf("%02x", mdbuf[i] & 0xFF);
	}
	printf("\n");

	//BIO_free_all(boutfile);
	//BIO_free_all(hash);
	
	return 0;
}


//This function offers an example of chaining a DES cipher to a base 64 encoder
//  to a buffer to a file, using BIOs. Taken almost directly from the example code
//  in the book "Network Security with OpenSSL". The concepts should be useful
//  for preparing the RSA hash and signature.
//  Uncomment the function to try it out.
/*
int write_data(const char *filename, char *out, int len, unsigned char *key)
{
    int total, written;
    BIO *cipher, *b64, *buffer, *file;
    // Create a buffered file BIO for writing
    file = BIO_new_file(filename, "w") ;
    if (! file)
        return 0;
    // Create a buffering filter BIO to buffer writes to the file
    buffer = BIO_new(BIO_f_buffer( ));
    // Create a base64 encoding filter BIO
    b64 = BIO_new(BIO_f_base64( ));
    // Create the cipher filter BIO and set the key.  The last parameter of
    // BIO_set_cipher is 1 for encryption and 0 for decryption
    cipher = BIO_new(BIO_f_cipher( ));
    BIO_set_cipher(cipher, EVP_des_ede3_cbc( ), key, NULL, 1);
    // Assemble the BIO chain to be in the order cipher-b64-buffer-file

    BIO_push(cipher, b64);
    BIO_push(b64, buffer);
    BIO_push(buffer, file);
    // This loop writes the data to the file.  It checks for errors as if the
    // underlying file were non-blocking
    for (total = 0;  total < len;  total += written)
    {
        if ((written = BIO_write(cipher, out + total, len - total) ) <= 0)
        {
            if (BIO_should_retry(cipher) )
            {
                written = 0;
                continue;
            }
            break;
        }
    }
    // Ensure all of our data is pushed all the way to the file
    BIO_flush(cipher) ;
    // We now need to free the BIO chain. A call to BIO_free_all(cipher) would
    // accomplish this, but we' ll first remove b64 from the chain for
    // demonstration purposes.
    BIO_pop(b64) ;
    // At this point the b64 BIO is isolated and the chain is cipher-buffer-file.
    // The following frees all of that memory
    BIO_free(b64) ;
    BIO_free_all(cipher) ;
	return 0;
}
*/
