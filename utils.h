// Macro definitions
#define BUFFER_SIZE 1024
#define PAUSE(X) for(uint now=time(NULL); time(NULL) != now+X;) {}

//----------------------------------------------------------------------------
// Function: print_errors()
// The function prints all errors present in the crypto system
//----------------------------------------------------------------------------
void print_errors()
{
    char buff[BUFFER_SIZE];
    int error;
    while ((error = ERR_get_error()) != 0) {
        ERR_error_string_n(error, buff, sizeof(buff));
        printf("*** %s\n", buff);
    }
}

//----------------------------------------------------------------------------
// Function: buff2hex(buf,len)
// Input (buff): An array of bytes
// Input (len): Number of bytes in the array
// Return: A hex representation of (len) bytes of (buf) in a string
//----------------------------------------------------------------------------
string buff2hex(const unsigned char* buff, const int len)
{
    string s = "";
    for(uint i = 0; i < len; i++)
    {
        char temp[EVP_MAX_MD_SIZE];
        sprintf(temp, "%02x", buff[i] & 0xFF);
        s += temp;
    }
    return s;
}