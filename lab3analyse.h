//
// Created by zxggx on 10.11.2023.
//

#ifndef RC5_LAB3ANALYSIS_H
#define RC5_LAB3ANALYSIS_H

#include <vector>
#include <cstdint>

double countCorell(const std::vector<unsigned char> &plain, const std::vector<unsigned char> &cipher);

double autocorrelationTest(const std::vector<unsigned char> &sequence);

void frequencyTest(const std::vector<unsigned char> &sequence);

double serialTest(const std::vector<unsigned char> &sequence);

int countSerials(const std::vector<unsigned char> &sequence, size_t serialLength);

#endif // RC5_LAB3ANALYSIS_H
