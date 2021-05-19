#ifndef _BASE64_H_
#define _BASE64_H_

#include <vector>
#include <string>

std::string Base64Encode(const std::vector<unsigned char> &inputKey);
std::vector<unsigned char> Base64Decode(std::string const &inputStr);

#endif
