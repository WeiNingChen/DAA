#include <iostream>
#include <string>
#include <vector>
#include <gmp.h>
#include <gmpxx.h>

using namespace std;

// int mpz_set_str(mpz_t rop, const char* str, int base)
// return 0 valid, otherwise, return -1 
mpz_class
myStr2Int(const string& str, const int& base)
{
    mpz_class num = 0;
    size_t i = 0;
    for (; i < str.size(); ++i) {
        int digit;
        if (isdigit(str[i])) digit = int(str[i] - '0');
        else digit = int(str[i] - 'a') + 10; 
        num *= base;
        num += digit;
    }
    return num;
}

string
myInt2Str(int num, const int& base)
{
    string str_num;
    do{
        if (num % base >= 10) str_num = char(num % base - 10 + int('a')) + str_num;
        else str_num = char(num % base + int('0')) + str_num;
        num /= base;
    } while (num > 0);
    return str_num;
}
