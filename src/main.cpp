#include "crypto.hpp"
#include <iostream>





int main(int argc, char** argv){

    //std::string s = "Hello world!";
    char s3[13] = "Hello World!";
    sha256 sha = sha2(reinterpret_cast<const uint8_t*>(s3),12);
    sha2 sh = sha256(reinterpret_cast<const uint8_t*>(s3),12);
	uint8_t * digest = sha.digest();
	std::cout << sha256::toString(digest) << std::endl;
    std::cout<<std::string(sha)<<std::endl;
    std::cout<<sh.toHexadec()<<std::endl;
    

    return 0;
}