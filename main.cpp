#include <map>
#include <set>
#include <iostream>
#include <string>
#include "AES.h"
#include <fstream>
using namespace std;
std::vector<unsigned char> iv = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                 0xff, 0xff, 0xff, 0xff};
std::vector<unsigned char> key = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
const unsigned int BLOCK_BYTES_LENGTH = 16 * sizeof(unsigned char);

void decipher()
{
    AES aes(AESKeyLength::AES_256);
    std::vector<unsigned char> in = aes.bytesFromImage("output.bmp");
    std::vector<unsigned char> innew = aes.DecryptCBC(in, key, iv);
    aes.fileFromBytes("decipheredOutput.bmp", innew);
}

int main()
{

    AES aes(AESKeyLength::AES_256);
    unsigned char plain[] = {'I', 'a', 'm', 't', 'i', 'r', 'e', 'd',
                             'I', 'a', 'm', 't', 'i', 'r', 'e', '\0'};

    // std::vector<unsigned char> in = aes.bytesFromImage("input.bmp");
    // std::vector<unsigned char> out = aes.EncryptCBC(in, key, iv);

    // aes.fileFromBytes("output.bmp", out);

    decipher();

    return 0;
}
