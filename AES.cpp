#include "AES.h"
#include <iostream>
#include <fstream>
#include <vector>
using namespace std;
AES::AES(const AESKeyLength keyLength)
{
    switch (keyLength)
    {
    case AESKeyLength::AES_128:
        this->Nk = 4;
        this->Nr = 10;
        break;
    case AESKeyLength::AES_192:
        this->Nk = 6;
        this->Nr = 12;
        break;
    case AESKeyLength::AES_256:
        this->Nk = 8;
        this->Nr = 14;
        break;
    }
}

unsigned char *AES::EncryptCBC(unsigned char in[], unsigned int inLen,
                               const unsigned char key[],
                               const unsigned char *iv)
{

    unsigned char *out = new unsigned char[inLen];
    unsigned char block[blockBytesLen];
    unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion(key, roundKeys);
    memcpy(block, iv, blockBytesLen);
    unsigned int i = 0;
    for (i = 0; i < inLen; i += blockBytesLen)
    {
        XorBlocks(block, in + i, block, blockBytesLen);
        EncryptBlock(block, out + i, roundKeys);
        memcpy(block, out + i, blockBytesLen);
    }
    delete[] roundKeys;

    return out;
}

unsigned char *AES::DecryptCBC(const unsigned char in[], unsigned int inLen,
                               const unsigned char key[],
                               const unsigned char *iv)
{
    unsigned char *out = new unsigned char[inLen];
    unsigned char block[blockBytesLen];
    unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion(key, roundKeys);
    memcpy(block, iv, blockBytesLen);
    for (unsigned int i = 0; i < inLen; i += blockBytesLen)
    {
        DecryptBlock(in + i, out + i, roundKeys);
        XorBlocks(block, out + i, out + i, blockBytesLen);
        memcpy(block, in + i, blockBytesLen);
    }

    delete[] roundKeys;

    return out;
}

void AES::EncryptBlock(const unsigned char in[], unsigned char out[],
                       unsigned char *roundKeys)
{
    unsigned char state[4][Nb];
    unsigned int i, j, round;

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++)
        {
            state[i][j] = in[i + 4 * j];
        }
    }

    AddRoundKey(state, roundKeys);

    for (round = 1; round <= Nr - 1; round++)
    {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + round * 4 * Nb);
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + Nr * 4 * Nb);

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++)
        {
            out[i + 4 * j] = state[i][j];
        }
    }
}

void AES::DecryptBlock(const unsigned char in[], unsigned char out[],
                       unsigned char *roundKeys)
{
    unsigned char state[4][Nb];
    unsigned int i, j, round;

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++)
        {
            state[i][j] = in[i + 4 * j];
        }
    }

    AddRoundKey(state, roundKeys + Nr * 4 * Nb);

    for (round = Nr - 1; round >= 1; round--)
    {
        InvSubBytes(state);
        InvShiftRows(state);
        AddRoundKey(state, roundKeys + round * 4 * Nb);
        InvMixColumns(state);
    }

    InvSubBytes(state);
    InvShiftRows(state);
    AddRoundKey(state, roundKeys);

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++)
        {
            out[i + 4 * j] = state[i][j];
        }
    }
}

void AES::SubBytes(unsigned char state[4][Nb])
{
    unsigned int i, j;
    unsigned char t;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++)
        {
            t = state[i][j];
            state[i][j] = sbox[t / 16][t % 16];
        }
    }
}

void AES::ShiftRow(unsigned char state[4][Nb], unsigned int i,
                   unsigned int n) // shift row i on n positions
{
    unsigned char tmp[Nb];
    for (unsigned int j = 0; j < Nb; j++)
    {
        tmp[j] = state[i][(j + n) % Nb];
    }
    memcpy(state[i], tmp, Nb * sizeof(unsigned char));
}

void AES::ShiftRows(unsigned char state[4][Nb])
{
    ShiftRow(state, 1, 1);
    ShiftRow(state, 2, 2);
    ShiftRow(state, 3, 3);
}

unsigned char AES::xtime(unsigned char b) // multiply on x
{
    return (b << 1) ^ (((b >> 7) & 1) * 0x1b);
}

void mixSingleColumn(unsigned char *r)
{
    unsigned char a[4];
    unsigned char b[4];
    unsigned char c;
    unsigned char h;
    /* The array 'a' is simply a copy of the input array 'r'
     * The array 'b' is each element of the array 'a' multiplied by 2
     * in Rijndael's Galois field
     * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */
    for (c = 0; c < 4; c++)
    {
        a[c] = r[c];
        /* h is 0xff if the high bit of r[c] is set, 0 otherwise */
        h = (unsigned char)((signed char)r[c] >> 7); /* arithmetic right shift, thus shifting in either zeros or ones */
        b[c] = r[c] << 1;                            /* implicitly removes high bit because b[c] is an 8-bit char, so we xor by 0x1b and not 0x11b in the next line */
        b[c] ^= 0x1B & h;                            /* Rijndael's Galois field */
    }
    r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; /* 2 * a0 + a3 + a2 + 3 * a1 */
    r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; /* 2 * a1 + a0 + a3 + 3 * a2 */
    r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; /* 2 * a2 + a1 + a0 + 3 * a3 */
    r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; /* 2 * a3 + a2 + a1 + 3 * a0 */
}

/* Performs the mix columns step. Theory from: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_MixColumns_step */
void AES::MixColumns(unsigned char state[4][Nb])
{
    unsigned char *temp = new unsigned char[4];

    for (int i = 0; i < 4; ++i)
    {
        for (int j = 0; j < 4; ++j)
        {
            temp[j] = state[j][i]; // place the current state column in temp
        }
        mixSingleColumn(temp); // mix it using the wiki implementation
        for (int j = 0; j < 4; ++j)
        {
            state[j][i] = temp[j]; // when the column is mixed, place it back into the state
        }
    }
    delete temp;
}

void AES::AddRoundKey(unsigned char state[4][Nb], unsigned char *key)
{
    unsigned int i, j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++)
        {
            state[i][j] = state[i][j] ^ key[i + 4 * j];
        }
    }
}

// void AES::SubWord(unsigned char *a)
// {
//     int i;
//     for (i = 0; i < 4; i++)
//     {
//         a[i] = sbox[a[i] / 16][a[i] % 16];
//     }
// }

void AES::SubWord(unsigned char *a)
{
    unsigned int a1[] = {0b10001111, 0b11000111, 0b11100011, 0b11110001, 0b11111000, 0b01111100, 0b00111110, 0b00011111};
    unsigned int b = 0b11000110;
    for (int i = 0; i < 4; i++)
    {
        a[i] = (a1[i] * a[i]) ^ b;
    }
}

void AES::RotWord(unsigned char *a)
{
    unsigned char c = a[0];
    a[0] = a[1];
    a[1] = a[2];
    a[2] = a[3];
    a[3] = c;
}

void AES::XorWords(unsigned char *a, unsigned char *b, unsigned char *c)
{
    int i;
    for (i = 0; i < 4; i++)
    {
        c[i] = a[i] ^ b[i];
    }
}

void AES::Rcon(unsigned char *a, unsigned int n)
{
    unsigned int i;
    unsigned char c = 1;
    for (i = 0; i < n - 1; i++)
    {
        c = xtime(c);
    }

    a[0] = c;
    a[1] = a[2] = a[3] = 0;
}

void AES::KeyExpansion(const unsigned char key[], unsigned char w[])
{
    unsigned char temp[4];
    unsigned char rcon[4];

    unsigned int i = 0;
    while (i < 4 * Nk)
    {
        w[i] = key[i];
        i++;
    }

    i = 4 * Nk;
    while (i < 4 * Nb * (Nr + 1))
    {
        temp[0] = w[i - 4 + 0];
        temp[1] = w[i - 4 + 1];
        temp[2] = w[i - 4 + 2];
        temp[3] = w[i - 4 + 3];

        if (i / 4 % Nk == 0)
        {
            RotWord(temp);
            SubWord(temp);
            Rcon(rcon, i / (Nk * 4));
            XorWords(temp, rcon, temp);
        }
        else if (Nk > 6 && i / 4 % Nk == 4)
        {
            SubWord(temp);
        }

        w[i + 0] = w[i - 4 * Nk] ^ temp[0];
        w[i + 1] = w[i + 1 - 4 * Nk] ^ temp[1];
        w[i + 2] = w[i + 2 - 4 * Nk] ^ temp[2];
        w[i + 3] = w[i + 3 - 4 * Nk] ^ temp[3];
        i += 4;
    }
}

void AES::InvSubBytes(unsigned char state[4][Nb])
{
    unsigned char t;
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < Nb; j++)
        {
            t = state[i][j];
            state[i][j] = inv_sbox[t / 16][t % 16];
        }
    }
}

void AES::InvMixColumns(unsigned char state[4][Nb])
{
    unsigned char temp_state[4][Nb];

    for (size_t i = 0; i < 4; ++i)
    {
        memset(temp_state[i], 0, 4);
    }

    for (size_t i = 0; i < 4; ++i)
    {
        for (size_t k = 0; k < 4; ++k)
        {
            for (size_t j = 0; j < 4; ++j)
            {
                temp_state[i][j] ^= GF_MUL_TABLE[INV_CMDS[i][k]][state[k][j]];
            }
        }
    }

    for (size_t i = 0; i < 4; ++i)
    {
        memcpy(state[i], temp_state[i], 4);
    }
}

void AES::InvShiftRows(unsigned char state[4][Nb])
{
    ShiftRow(state, 1, Nb - 1);
    ShiftRow(state, 2, Nb - 2);
    ShiftRow(state, 3, Nb - 3);
}

void AES::XorBlocks(const unsigned char *a, const unsigned char *b,
                    unsigned char *c, unsigned int len)
{
    for (unsigned int i = 0; i < len; i++)
    {
        c[i] = a[i] ^ b[i];
    }
}

void AES::printHexArray(unsigned char a[], unsigned int n)
{
    for (unsigned int i = 0; i < n; i++)
    {
        printf("%02x ", a[i]);
    }
}

void AES::printHexVector(std::vector<unsigned char> a)
{
    for (unsigned int i = 0; i < a.size(); i++)
    {
        printf("%02x ", a[i]);
    }
}

std::vector<unsigned char> AES::ArrayToVector(unsigned char *a,
                                              unsigned int len)
{
    std::vector<unsigned char> v(a, a + len * sizeof(unsigned char));
    return v;
}

unsigned char *AES::VectorToArray(std::vector<unsigned char> &a)
{
    return a.data();
}

std::vector<unsigned char> AES::EncryptCBC(std::vector<unsigned char> in,
                                           std::vector<unsigned char> key,
                                           std::vector<unsigned char> iv)
{
    while (in.size() % blockBytesLen != 0)
    {
        in.push_back('\0');
    }
    unsigned char *out = EncryptCBC(VectorToArray(in), (unsigned int)in.size(),
                                    VectorToArray(key), VectorToArray(iv));
    std::vector<unsigned char> v = ArrayToVector(out, in.size());
    delete[] out;
    return v;
}

std::vector<unsigned char> AES::DecryptCBC(std::vector<unsigned char> in,
                                           std::vector<unsigned char> key,
                                           std::vector<unsigned char> iv)
{
    unsigned char *out = DecryptCBC(VectorToArray(in), (unsigned int)in.size(),
                                    VectorToArray(key), VectorToArray(iv));
    std::vector<unsigned char> v = ArrayToVector(out, (unsigned int)in.size());
    delete[] out;
    while (v.back() == '\0')
    {
        v.pop_back();
    }
    return v;
}

std::vector<uint8_t> AES::bytesFromFile(std::string inputFilePath)
{
    std::vector<uint8_t> bytesOfFile;
    std::ifstream file(inputFilePath, std::ios::binary);

    if (file)
    {
        file.seekg(0, std::ios::end);
        std::streampos fileSize = file.tellg();
        file.seekg(0, std::ios::beg);
        bytesOfFile.resize(static_cast<size_t>(fileSize));
        file.read(reinterpret_cast<char *>(bytesOfFile.data()), fileSize);
        file.close();
    }
    else
    {
        throw std::runtime_error("Failed to read file: " + inputFilePath);
    }
    this->dataBytes = bytesOfFile;
    return bytesOfFile;
}

std::string AES::fileFromBytes(const std::string &outputFilePath, std::vector<unsigned char> inp)
{
    std::vector<uint8_t> combinedBytes(headerBytes);
    combinedBytes.insert(combinedBytes.end(), inp.begin(), inp.end());

    std::ofstream file(outputFilePath, std::ios::binary);

    if (file)
    {
        file.write(reinterpret_cast<const char *>(combinedBytes.data()), combinedBytes.size());
        file.close();
        return outputFilePath;
    }
    else
    {
        std::cerr << "Failed to create or write to file: " << outputFilePath << std::endl;
        throw std::runtime_error("Failed to create or write to file: " + outputFilePath);
    }
}

std::vector<unsigned char> AES::bytesFromImage(std::string inputFilePath)
{
    std::ifstream file(inputFilePath, std::ios::binary);
    if (!file)
    {
        throw std::runtime_error("Failed to read file: " + inputFilePath);
    }
    const size_t headerSize = 54;
    headerBytes.resize(headerSize);
    file.read(reinterpret_cast<char *>(headerBytes.data()), headerSize);

    file.seekg(0, std::ios::end);
    const size_t fileSize = file.tellg();
    const size_t pixelDataSize = fileSize - headerSize;

    dataBytes.resize(pixelDataSize);
    file.seekg(headerSize);
    file.read(reinterpret_cast<char *>(dataBytes.data()), pixelDataSize);

    file.close();

    return dataBytes;
}
