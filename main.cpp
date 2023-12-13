#include <map>
#include <set>
#include <iostream>
#include <string>
#include "AES.h"
#include <fstream>
#include <random>
#include <time.h>
#include <cstdint>
#include "lab3analyse.h"
#include <windows.h>
#include <bitset>
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
    // for (int i = 0; i < 1; ++i)
    // {
    //     out[i] = 0x0;
    // }
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

// double calculateMean(const std::vector<uint8_t> &data)
// {
//     double sum = 0;
//     for (const uint32_t &value : data)
//     {
//         sum += value;
//     }
//     return sum / data.size();
// }

// Функция для вычисления среднеквадратического отклонения

void getCorrel()
{
    AES aes(AESKeyLength::AES_256);
    std::vector<uint8_t> in = aes.bytesFromImage("input.bmp");
    std::vector<uint8_t> out = aes.bytesFromImage("output.bmp");
    cout << "Corrl: " << countCorell(in, out);
}

void invertSecondBits(std::vector<unsigned char> &block)
{
    for (unsigned char &i : block)
    {
        i ^= (0xFF >> 4);
    }
}

void invertEvenBits(std::vector<unsigned char> &block)
{
    for (unsigned char &i : block)
    {
        i ^= 0xAAAAAAAA;
    }
}

void visualizeDifferingBits(const std::vector<unsigned char> &data1, const std::vector<unsigned char> &data2)
{
    for (size_t i = 0; i < data1.size(); ++i)
    {
        std::bitset<8> bits1(data1[i]);
        std::bitset<8> bits2(data2[i]);
        for (int j = 0; j < 8; ++j)
        {
            if (bits1[j] != bits2[j])
            {
                std::cout << "\x1B[31m" << bits1[j] << "\x1B[0m";
            }
            else
            {
                std::cout << "\x1B[32m" << bits1[j] << "\x1B[0m";
            }
        }
    }
    std::cout << endl;
    for (size_t i = 0; i < data1.size(); ++i)
    {
        std::bitset<8> bits1(data1[i]);
        std::bitset<8> bits2(data2[i]);
        for (int j = 0; j < 8; ++j)
        {
            if (bits1[j] != bits2[j])
            {
                std::cout << "\x1B[31m" << bits2[j] << "\x1B[0m";
            }
            else
            {
                std::cout << "\x1B[32m" << bits2[j] << "\x1B[0m";
            }
        }
    }
    std::cout << endl;
}

void lab3(std::vector<unsigned char> key)
{
    AES aes(AESKeyLength::AES_256);
    std::vector<unsigned char> in = {'B', 'A', 'Q', 'C', 'G', 'F', 'K', 'O', 'F', '9', 'A', 'B', 'C', 'D', 'E', '\0'};
    invertSecondBits(in);
    cout << "Inverted second part bits: " << in.data() << endl;
    std::vector<unsigned char> out1 = aes.EncryptCBC(in, key, iv);
    cout << "Ciphered with inversed second part bits: " << out1.data() << endl;
    std::vector<unsigned char> in2 = {'B', 'A', 'Q', 'C', 'G', 'F', 'K', 'O', 'F', '9', 'A', 'B', 'C', 'D', 'E', '\0'};
    invertEvenBits(in2);
    cout << "Inverted first part bits: " << in2.data() << endl;
    std::vector<unsigned char> out2 = aes.EncryptCBC(in2, key, iv);
    cout << "Ciphered with Inverted first part bits: " << out2.data() << endl;
    std::cout << "AutoCorrel. block with inverted second part: " << autocorrelationTest(out1) << std::endl;
    std::cout << "AutoCorrel. block with inverted first part bits: " << autocorrelationTest(out2) << std::endl;
    std::cout << "Serial test. block with inverted second part: " << serialTest(out1) << std::endl;
    std::cout << "Serial test. block with inverted first part bits: " << serialTest(out2) << std::endl;
    visualizeDifferingBits(out1, out2);
    frequencyTest(out1);
    frequencyTest(out2);
}

int main()
{
    setlocale(LC_ALL, "Russian");
    SetConsoleOutputCP(866);
    std::vector<unsigned char> key = getRandomKey();
    cout << "Generated key: " << key.data() << endl;
    AES aes(AESKeyLength::AES_256);
    lab3(key);
    // cipherImage(key);
    // decipherImage(key);
    // getCorrel();
    // cipherText(key);
    // decipherText(key);
    return 0;
}
