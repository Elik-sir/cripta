#include <map>
#include <set>
#include <iostream>
#include <string>
#include "AES.h"
#include <fstream>
#include <random>
#include <time.h>
int myseed = 1234;

using namespace std;
std::vector<unsigned char> iv = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                 0xff, 0xff, 0xff, 0xff};

const unsigned int BLOCK_BYTES_LENGTH = 16 * sizeof(unsigned char);
std::vector<unsigned char> getRandomKey()
{
    srand((unsigned)time(NULL));
    std::vector<unsigned char> key;
    for (int i = 0; i < 32; i++)
    {
        key.push_back(rand() % 256);
    }
    return key;
}

std::vector<unsigned char> writeKey()
{
    std::string str;
    cout << "Write your key: ";
    cin >> str;

    std::vector<unsigned char> key;
    for (int i = 0; i < str.size(); i++)
    {
        key.push_back(str[i]);
    }
    return key;
}

std::vector<unsigned char> getVectorFromStr(std::string input)
{
    std::vector<unsigned char> key;
    for (int i = 0; i < input.size(); i++)
    {
        key.push_back(input[i]);
    }
    return key;
}

void cipherImage(std::vector<unsigned char> key)
{
    AES aes(AESKeyLength::AES_256);
    std::vector<unsigned char> in = aes.bytesFromImage("input.bmp");
    std::vector<unsigned char> out = aes.EncryptCBC(in, key, iv);
    aes.fileFromBytes("output.bmp", out);
}

void decipherImage(std::vector<unsigned char> key)
{
    AES aes(AESKeyLength::AES_256);
    std::vector<unsigned char> in = aes.bytesFromImage("output.bmp");
    std::vector<unsigned char> innew = aes.DecryptCBC(in, key, iv);
    aes.fileFromBytes("decipheredOutput.bmp", innew);
}

void cipherText(std::vector<unsigned char> key)
{
    AES aes(AESKeyLength::AES_256);
    std::vector<unsigned char> in = aes.bytesFromFile("test.txt");
    std::vector<unsigned char> out = aes.EncryptCBC(in, key, iv);
    aes.fileFromBytes("textOutput.txt", out);
}

void decipherText(std::vector<unsigned char> key)
{
    AES aes(AESKeyLength::AES_256);
    std::vector<unsigned char> in = aes.bytesFromFile("textOutput.txt");
    std::vector<unsigned char> innew = aes.DecryptCBC(in, key, iv);
    aes.fileFromBytes("decipheredOutputText.txt", innew);
}

int main()
{
    std::vector<unsigned char> key = getRandomKey();
    cout << "Generated key: " << key.data() << endl;
    AES aes(AESKeyLength::AES_256);
    // cipherImage(key);
    // decipherImage(key);
    cipherText(key);
    decipherText(key);

    return 0;
}
