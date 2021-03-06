//----------------------------------------------------------------------------
// File: ssl_server.cpp
// Description: Implementation of an SSL-secured server that performs
//              secure file transfer to a single client over a single
//              connection.
//----------------------------------------------------------------------------
#include <string>
#include <iostream>
#include <time.h>
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>

#include "utils.h"

//-----------------------------------------------------------------------------
// Function: main()
//-----------------------------------------------------------------------------
int main(int argc, char** argv)
{
    //-------------------------------------------------------------------------
    // initialize
	ERR_load_crypto_strings();
	SSL_load_error_strings();
  SSL_library_init();
    
    setbuf(stdout, NULL); // disables buffered output

	// Handle commandline arguments
	// Useage: client -server serveraddress -port portnumber filename
	if (argc < 2)
	{
		printf("Useage: server portnumber\n");
		exit(EXIT_FAILURE);
	}
	char* port = argv[1];

	printf("------------\n");
	printf("-- SERVER --\n");
	printf("------------\n");

    //-------------------------------------------------------------------------
	// 1. Allow for a client to establish an SSL connection
	printf("1. Allowing for client SSL connection...");

	// Setup DH object and generate Diffie-Helman Parameters
	DH* dh = DH_generate_parameters(128, 5, NULL, NULL);
	int dh_err;
	DH_check(dh, &dh_err);
	if (dh_err != 0)
	{
		printf("Error during Diffie-Helman parameter generation.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup server context
	SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
//	SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_SINGLE_DH_USE);
	SSL_CTX_set_tmp_dh(ctx, dh);
	if (SSL_CTX_set_cipher_list(ctx, "ALL") != 1)
	{
		printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup the BIO
	BIO* server = BIO_new(BIO_s_accept());
	BIO_set_accept_port(server, port);
	BIO_do_accept(server);

	// Setup the SSL
	SSL* ssl = SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating new SSL object from context.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}
	SSL_set_accept_state(ssl);
	SSL_set_bio(ssl, server, server);
	if (SSL_accept(ssl) <= 0)
	{
		printf("Error doing SSL_accept(ssl).\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	printf("DONE.\n");
	printf("    (Now listening on port: %s)\n", port);

    //-------------------------------------------------------------------------
	// 2. Receive a random number (the challenge) from the client
	printf("2. Waiting for client to connect and send challenge...");
    unsigned char enc_rbuf[128] = {0};
    unsigned char rbuf[128] = {0};
    SSL_read(ssl,enc_rbuf, 128);
    
    BIO* b_rsap = BIO_new_file("rsaprivatekey.pem", "r");

    RSA* rsa_enc = PEM_read_bio_RSAPrivateKey(b_rsap, NULL, NULL, NULL);
    RSA_private_decrypt(128, (unsigned char*)enc_rbuf, (unsigned char*)rbuf ,rsa_enc, RSA_PKCS1_PADDING); 

    
	printf("DONE.\n");
	printf("    (Challenge (unHashed | Decrypted): \"%s\")\n", buff2hex((const unsigned char*)rbuf, 20).c_str());

    //-------------------------------------------------------------------------
	// 3. Generate the SHA1 hash of the challenge
	printf("3. Generating SHA1 hash...");

  //char infilename[1024] = {0};
  //BIO * infile = BIO_new_file(infilename, "r");
  
  char send_buff[128] = {0};

  //block memory for the input file
	BIO* infile = BIO_new(BIO_s_mem());

  //create and set hash type
 	BIO* hash = BIO_new(BIO_f_md());
	BIO_set_md(hash, EVP_sha1());
  
  //chain the hash and the infile
	BIO_push(infile, hash);
  
  //write to bio (hashing it) then pull out the chars
	BIO_write(infile,rbuf, 128);
	//BIO_gets(hash, send_buff, 128);
  BIO_read(infile, send_buff, 128);
  //cout << "\n\n\n" << endl;
  //for (int i = 0; i < 6; i++) {
  //  printf("\n--%c--\n", send_buff[i]); 
  //}
  //write to the socket
  
  int mdlen= 20; //BIO_gets(hash, h_buff, EVP_MAX_MD_SIZE);
	string hash_string = send_buff;

	printf("SUCCESS.\n");
	printf("    (SHA1 hash: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)send_buff, 20).c_str(), mdlen); //hash_string.c_str(), mdlen);

    //-------------------------------------------------------------------------
	// 4. Sign the key using the RSA private key specified in the
	//     file "rsaprivatekey.pem"
	printf("4. Signing the key...");


    char enc_buff[128] = {0};

    int rsa_size = RSA_private_encrypt(20, (unsigned char*)send_buff, (unsigned char*)enc_buff ,rsa_enc, RSA_PKCS1_PADDING); 

    int siglen= 20;
    char* signature= enc_buff;
    
    //cout << rsa_size <<  endl;

    printf("DONE.\n");
    printf("    (Signed key length: %d bytes)\n", siglen);
    printf("    (Signature (Hashed, Encrypted): \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)enc_buff, 20).c_str(), siglen);

    //-------------------------------------------------------------------------
	// 5. Send the signature to the client for authentication
	printf("5. Sending signature to client for authentication...");

	//BIO_flush
	//SSL_write

  SSL_write(ssl, enc_buff, 128);
    
    printf("DONE.\n");
    
    //-------------------------------------------------------------------------
	// 6. Receive a filename request from the client
	printf("6. Receiving file request from client...");

    char file[BUFFER_SIZE] = {0};
    SSL_read(ssl, file, BUFFER_SIZE);
    //memset(file,0,sizeof(file));

    printf("RECEIVED.\n");
    printf("    (File requested: \"%s\"\n", file);

    //-------------------------------------------------------------------------
	// 7. Send the requested file back to the client (if it exists)
	printf("7. Attempting to send requested file to client...");

	PAUSE(2);
	BIO* sendfile = BIO_new_file(file,"r");
	char filebuff[1024] = {0};
  char encout_buff[1024] = {0};
  //BIO_puts(server, "fnf");
  int bytesSent=0;
  while(1) {
  int bread = BIO_read(sendfile, filebuff, BUFFER_SIZE);
  BIO_flush(sendfile);
    if (bread) {
      //RSA_private_encrypt(20, (unsigned char*)filebuff, (unsigned char*)encout_buff ,rsa_enc, RSA_PKCS1_PADDING);
      SSL_write(ssl, filebuff, bread);
	  }
    else break;
    bytesSent += bread;
  }
    
    printf("SENT.\n");
    printf("    (Bytes sent: %d)\n", bytesSent);
  
    //-------------------------------------------------------------------------
	// 8. Close the connection
	printf("8. Closing connection...");

	SSL_shutdown(ssl);
  //BIO_reset
    printf("DONE.\n");

    printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");
	
    //-------------------------------------------------------------------------
	// Freedom!
    
	BIO_free_all(server);
	return EXIT_SUCCESS;
}
