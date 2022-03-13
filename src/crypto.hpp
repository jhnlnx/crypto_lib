
#include <string>
#include <cstring>
#include <iomanip>

class sha256 {

public:
    sha256(const uint8_t* data, size_t length);
	uint8_t * digest();
	std::string static toString(const uint8_t * digest);
    std::string toHexadec();
    operator std::string() const;

private:
	uint8_t  m_data[64],* m_digset = new uint8_t[32];
	uint32_t m_blocklen,m_state[8];
	uint64_t m_bitlen;
	static uint32_t rot(uint32_t x, uint32_t n);
	void transform();
	void pad();
	void revert();
}typedef(sha2);



class sha3 {

public:
	sha3();
	~sha3();
private:
    
};

