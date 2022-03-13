#include "crypto.hpp"


// Symetric Ciphers
// Block Ciphers
// Triple DES
// AES

//
// Stream Ciphers
// ChaCha20-PoLY1305
// RC4
//
// Diffie-Hellman key exchange + DF Elliptic curves
// Asymetric Ciphers
// RSA
// ElGamal
// ECC
//
// Certificates
// Public/Private Key (PKI)
//
// Hash Functions

// SHA-2 (256)
sha256::sha256(const uint8_t * data, size_t length){
    m_blocklen = 0;
    m_bitlen = 0;
	m_state[0] = 0x6a09e667;
	m_state[1] = 0xbb67ae85;
	m_state[2] = 0x3c6ef372;
	m_state[3] = 0xa54ff53a;
	m_state[4] = 0x510e527f;
	m_state[5] = 0x9b05688c;
	m_state[6] = 0x1f83d9ab;
	m_state[7] = 0x5be0cd19;
    for (size_t i = 0 ; i < length ; i++) {
		m_data[m_blocklen++] = data[i];
		if (m_blocklen == 64) {
			transform();
			m_bitlen += 512;
			m_blocklen = 0;
		}
	}
    pad();
	revert();
}

uint8_t * sha256::digest() {
	return m_digset;
}

uint32_t sha256::rot(uint32_t x, uint32_t n) {
	return (x >> n) | (x << (32 - n));
}

void sha256::transform() {
	uint32_t maj, xorA, ch, xorE, sum, newA, newE, m[64];
	uint32_t state[8];

	for (uint8_t i = 0, j = 0; i < 16; i++, j += 4)
		m[i] = (m_data[j] << 24) | (m_data[j + 1] << 16) | (m_data[j + 2] << 8) | (m_data[j + 3]);
	

	for (uint8_t k = 16 ; k < 64; k++) 
		m[k] = (sha256::rot(m[k - 2],17)^sha256::rot(m[k - 2],19)^(m[k - 2]>>10)) + m[k - 7] + (sha256::rot(m[k - 15],7)^sha256::rot(m[k - 15],18)^(m[k - 15]>>3)) + m[k - 16];
	

	for(uint8_t i = 0 ; i < 8 ; i++) 
		state[i] = m_state[i];
	
    static constexpr std::array<uint32_t, 64> K = {
		0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
		0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
		0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
		0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
		0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
		0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
		0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
		0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
		0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
		0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
		0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
		0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
		0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
		0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
		0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
		0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
	};

	for (uint8_t i = 0; i < 64; i++) {
		maj   = (state[0]&( state[1] | state[2]))|(state[1] & state[2]);
		xorA  = sha256::rot(state[0], 2) ^ sha256::rot(state[0], 13) ^ sha256::rot(state[0], 22);

		ch = (state[4]& state[5])^(~state[4] & state[6]);

		xorE  = sha256::rot(state[4], 6) ^ sha256::rot(state[4], 11) ^ sha256::rot(state[4], 25);

		sum  = m[i] + K[i] + state[7] + ch + xorE;
		newA = xorA + maj + sum;
		newE = state[3] + sum;

		state[7] = state[6];
		state[6] = state[5];
		state[5] = state[4];
		state[4] = newE;
		state[3] = state[2];
		state[2] = state[1];
		state[1] = state[0];
		state[0] = newA;
	}

	for(uint8_t i = 0 ; i < 8 ; i++) 
		m_state[i] += state[i];
	
}

void sha256::pad() {

	uint64_t i = m_blocklen;
	uint8_t end = m_blocklen < 56 ? 56 : 64;

	m_data[i++] = 0x80;
	while (i < end) {
		m_data[i++] = 0x00;
	}

	if(m_blocklen >= 56) {
		transform();
		memset(m_data, 0, 56);
	}
	m_bitlen += m_blocklen * 8;
	m_data[63] = m_bitlen;
	m_data[62] = m_bitlen >> 8;
	m_data[61] = m_bitlen >> 16;
	m_data[60] = m_bitlen >> 24;
	m_data[59] = m_bitlen >> 32;
	m_data[58] = m_bitlen >> 40;
	m_data[57] = m_bitlen >> 48;
	m_data[56] = m_bitlen >> 56;
	transform();
}

void sha256::revert() {
	for (uint8_t i = 0 ; i < 4 ; i++) {
		for(uint8_t j = 0 ; j < 8 ; j++) {
			m_digset[i + (j * 4)] = (m_state[j] >> (24 - i * 8)) & 0x000000ff;
		}
	}
}

std::string sha256::toString(const uint8_t * digest) {
    std::stringstream s;
    s << std::setfill('0') << std::hex;
    for(uint8_t i=0; i<32;i++)
        s << std::setw(2) << (unsigned int) digest[i];
    return s.str();
}

std::string sha256::toHexadec(){
    std::stringstream s;
    s << std::setfill('0') << std::hex;
    for(uint8_t i=0; i<32;i++)
        s << std::setw(2) << (unsigned int) m_digset[i];
    return s.str();
}

sha256::operator std::string() const{
    std::stringstream s;
    s << std::setfill('0') << std::hex;
    for(uint8_t i=0; i<32;i++)
        s << std::setw(2) << (unsigned int) m_digset[i];
    return s.str();
}


// SHA-3
// AEAD
// GOST


