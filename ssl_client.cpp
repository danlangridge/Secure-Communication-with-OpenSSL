//----------------------------------------------------------------------------
// File: ssl_client.cpp
// Description: Implementation of an SSL-secured client that performs
//              secure file transfer with a single server over a single
//              connection
//----------------------------------------------------------------------------
#include <string>
#include <time.h>               // to seed random number generator
#include <iostream>
#include <sstream>          // stringstreams
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>	// ERR_get_error()
#include <openssl/dh.h>		// Diffie-Helman algorithms & libraries
#include <openssl/rand.h>


#include "utils.h"

//----------------------------------------------------------------------------
// Function: main()
//----------------------------------------------------------------------------
int main(int argc, char** argv)
{
	//-------------------------------------------------------------------------
    // Initialization

    ERR_load_crypto_strings();
    SSL_library_init();
    SSL_load_error_strings();

    setbuf(stdout, NULL); // disables buffered output
    
    // Handle commandline arguments
	// Useage: client server:port filename
	if (argc < 3)
	{
		printf("Useage: client -server serveraddress -port portnumber filename\n");
		exit(EXIT_FAILURE);
	}
	char* server = argv[1];
	char* filename = argv[2];
	
	printf("------------\n");
	printf("-- CLIENT --\n");
	printf("------------\n");

    //-------------------------------------------------------------------------
	// 1. Establish SSL connection to the server
	printf("1.  Establishing SSL connection with the server...");

	// Setup client context
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
//	SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
	if (SSL_CTX_set_cipher_list(ctx, "ADH") != 1)
	{
		printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
		exit(EXIT_FAILURE);
	}
	
	// Setup the BIO
	BIO* client = BIO_new_connect(server);
	if (BIO_do_connect(client) != 1)
	{
		printf("FAILURE.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup the SSL
    SSL* ssl=SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating new SSL object from context.\n");
		exit(EXIT_FAILURE);
	}
	SSL_set_bio(ssl, client, client);
	if (SSL_connect(ssl) <= 0)
	{
		printf("Error during SSL_connect(ssl).\n");
		print_errors();
		exit(EXIT_FAILURE);
	}

	printf("SUCCESS.\n");
	printf("    (Now connected to %s)\n", server);

    //-------------------------------------------------------------------------
	// 2. Send the server a random number
	printf("2.  Sending challenge to the server...");
    
   
    unsigned char rbuf[128] = {0};
    unsigned char enc_rbuf[128] = {0};
    RAND_bytes(rbuf, 128);

  	BIO* pub_key = BIO_new_file( "rsapublickey.pem", "r");
    BIO* store_key = BIO_new_file( "key_authentication.txt" , "w");
	  RSA* rsa_pub =  PEM_read_bio_RSA_PUBKEY(pub_key, NULL, NULL, NULL);  
    
    RSA_public_encrypt(20, rbuf, enc_rbuf, rsa_pub, RSA_PKCS1_PADDING);

    //string randomNumber="31337";
    //char* randbuf = (char *)randomNumber.c_str();
	  SSL_write(ssl, enc_rbuf, 128);
  
  
  printf("SUCCESS.\n");
	printf("    (Challenge sent: \"%s\")\n", buff2hex((const unsigned char *)rbuf, 20).c_str());

    //-------------------------------------------------------------------------
	// 3a. Receive the signed key from the server
	printf("3a. Receiving signed key from server...");

    char* buff[128]= {0};
    int len= 128;
	  int err = SSL_read(ssl, buff, len);

	printf("RECEIVED.\n");
	printf("    (Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)buff, 20).c_str(), len);

    //-------------------------------------------------------------------------
	// 3b. Authenticate the signed key
	printf("3b. Authenticating key...");

  char dec_buff[20] = {0};

	//BIO* ua_key = BIO_new(BIO_s_mem());

  RSA_public_decrypt(128, (unsigned char*)buff, (unsigned char*)dec_buff, rsa_pub, RSA_PKCS1_PADDING );


 /* 
  //---------Debug
  SSL_get_error(ssl,err);
  cout << "\n\n" << err << "\n\n";
  unsigned long er =  ERR_get_error();
  char er_buf[1024] = {0};
  ERR_error_string(er, er_buf); 
  printf( "ERROR : %s" , er_buf);
  cout << "\n\n" << endl;
  //---------
  */
  //BIO* test =   
  //BIO_free(ua_key);
	

	string generated_key= ""; //str(buff);
	string decrypted_key= ""; // str(dec_buff);
    
	printf("AUTHENTICATED\n");
	printf("    (Generated key: %s)\n", buff2hex((const unsigned char*)buff, 20).c_str());
	printf("    (Decrypted key: %s)\n", buff2hex((const unsigned char*)dec_buff, 20).c_str());

    //-------------------------------------------------------------------------
	// 4. Send the server a file request
	printf("4.  Sending file request to server...");

	PAUSE(2);
  //BIO * filenme = BIO_new_file(argc[3], "r");
	//BIO_flush();
  //BIO_puts();
  char* fbuf = filename;
	SSL_write(ssl, fbuf , 20);

    printf("SENT.\n");
	printf("    (File requested: \"%s\")\n", filename);

    //-------------------------------------------------------------------------
	// 5. Receives and displays the contents of the file requested
	printf("5.  Receiving response from server...");

  
  char read_buff[1024] = {0};
  char out_buff[1024] = {0};
  BIO* file_req = BIO_new_file("dump.txt","w");
  int o = 5;
  while(o) {
    SSL_read(ssl, read_buff, 1024);
	 
    RSA_public_decrypt(128, (unsigned char*)read_buff, (unsigned char*)out_buff, rsa_pub, RSA_PKCS1_PADDING);

    BIO_write(file_req, read_buff, 1024);
	  BIO_flush(file_req);
    o--;
  }
  
  //BIO_free

	printf("FILE RECEIVED.\n");

    //-------------------------------------------------------------------------
	// 6. Close the connection
	printf("6.  Closing the connection...");

	SSL_shutdown(ssl);
	
	printf("DONE.\n");
	
	printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");


    //-------------------------------------------------------------------------
	// Freedom!
	SSL_CTX_free(ctx);
	SSL_free(ssl);
	return EXIT_SUCCESS;	
}
