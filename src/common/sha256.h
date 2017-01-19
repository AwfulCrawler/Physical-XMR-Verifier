//Taken from stackoverflow

#include <string>
#include <openssl/sha.h>

void sha256(const std::string& str, unsigned char* hash)
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.data(), str.size());
    SHA256_Final(hash, &sha256);
}
