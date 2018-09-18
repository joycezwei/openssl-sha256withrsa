//
// Created by parallels on 9/13/18.
//

#ifndef UNTITLED_3_COMMON_TOOL_H
#define UNTITLED_3_COMMON_TOOL_H

#include <iostream>
#include <cstring>

#include "openssl/sha.h"
#include "openssl/rsa.h"
#include "openssl/rand.h"
#include "openssl/objects.h"
#include "openssl/pem.h"


#include "Base64.h"

class common_tool {
public:
    static std::string url_encode(const std::string& szToEncode);
    static std::string url_decode(const std::string& szToDecode);
    static bool verify_rsa(RSA *rsa ,const std::string &content, const std::string &sign);
    static std::string sign(const char *private_key,const std::string &content);
    static void ERR(const char* string);
};


#endif //UNTITLED_3_COMMON_TOOL_H
