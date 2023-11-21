#include <valarray>
#include <iostream>
#include "lab3analyse.h"

// Функция для вычисления среднего значения
double calculateMean(const std::vector<unsigned char> &data)
{
    double sum = 0;
    for (const uint32_t &value : data)
    {
        sum += value;
    }
    return sum / data.size();
}

// Функция для вычисления среднеквадратического отклонения
double calculateStandardDeviation(const std::vector<unsigned char> &data, double mean)
{
    double variance = 0;
    for (const uint32_t &value : data)
    {
        variance += pow(value - mean, 2);
    }
    variance /= data.size();
    return sqrt(variance);
}

double countCorell(const std::vector<unsigned char> &plain, const std::vector<unsigned char> &cipher)
{

    double meanPlain = calculateMean(plain);
    double meanCipher = calculateMean(cipher);

    double stdDevPlain = calculateStandardDeviation(plain, meanPlain);
    double stdDevCipher = calculateStandardDeviation(cipher, meanCipher);

    double correlation = 0;
    for (size_t i = 0; i < plain.size(); ++i)
    {
        correlation += (plain[i] - meanPlain) * (cipher[i] - meanCipher);
    }
    correlation /= (stdDevPlain * stdDevCipher * plain.size());

    return correlation;
}

int calculateA(const std::vector<unsigned char> &sequence, size_t d)
{
    size_t n = sequence.size();
    int result = 0;

    for (size_t i = 0; i < n - d; ++i)
    {
        result += __builtin_popcount(sequence[i] ^ sequence[i + d]);
    }

    return result;
}

double autocorrelationTest(const std::vector<unsigned char> &sequence)
{
    size_t n = sequence.size();

    double sum = 0.0;
    for (size_t d = 1; d <= n / 2; ++d)
    {
        int A_d = calculateA(sequence, d);
        double X5 = 2.0 * (A_d - (n - d)) / std::sqrt(n - d);

        sum += X5;
    }
    return sum / (n / 2);
}

int countSerials(const std::vector<unsigned char> &sequence, size_t serialLength)
{
    size_t n = sequence.size() * 32;
    int count = 0;

    for (size_t i = 0; i < n - serialLength + 1; ++i)
    {
        uint32_t currentBits = sequence[i / 32] >> (i % 32);
        uint32_t mask = (1 << serialLength) - 1;

        if ((currentBits & mask) == (currentBits << (32 - serialLength) & mask))
        {
            ++count;
            i += serialLength - 1;
        }
    }

    return count;
}

double serialTest(const std::vector<unsigned char> &sequence)
{
    size_t n = sequence.size() * 32;
    size_t k = 0;

    while ((n - k + 3) >= (1 << (k + 2)))
    {
        ++k;
    }

    std::vector<double> ei(k, 0.0);
    for (size_t i = 1; i <= k; ++i)
    {
        ei[i - 1] = static_cast<double>(n - i + 3) / static_cast<double>(1 << (i + 2));
    }

    std::vector<int> Bi(k, 0);
    std::vector<int> Gi(k, 0);

    for (size_t i = 1; i <= k; ++i)
    {
        Bi[i - 1] = countSerials(sequence, i);
        Gi[i - 1] = n - Bi[i - 1];
    }

    double X4 = 0.0;

    for (size_t i = 0; i < k; ++i)
    {
        X4 += std::pow(Bi[i] - ei[i], 2) / ei[i];
        X4 += std::pow(Gi[i] - ei[i], 2) / ei[i];
    }

    return X4;
}

void frequencyTest(const std::vector<unsigned char> &sequence)
{
    int n = sequence.size();
    int countZeros = 0;
    int countOnes = 0;

    for (int i = 0; i < n; ++i)
    {
        countZeros += (sequence[i] & 1) == 0 ? 1 : 0;
        countOnes += (sequence[i] & 1) == 1 ? 1 : 0;
    }

    double expectedFrequency = 0.5;

    std::cout << "Frequency test:" << std::endl;
    std::cout << "freq of 0: " << static_cast<double>(countZeros) / n << ", expected: " << expectedFrequency
              << std::endl;
    std::cout << "freq 1: " << static_cast<double>(countOnes) / n << ", expected: " << expectedFrequency << std::endl;
}

//
// Created by zxggx on 10.11.2023.
//
