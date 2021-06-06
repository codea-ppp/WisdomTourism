#ifndef SSL_HEPLER_H_
#define SSL_HEPLER_H_

#include <memory>

class ssl_heaper_impl;

class ssl_helper
{
public:
	void get_md5_hash(unsigned char dst[16], const unsigned char* src, size_t size);

	void MD5_cooking(unsigned char raw[16], unsigned char cook[32]);
	void MD5_rawing(unsigned char raw[16], unsigned char cook[32]);

	void cooking(unsigned char* raw, unsigned char* cook, int size);
	void rawing(unsigned char* raw, unsigned char* cook, int size);

	ssl_helper();
	~ssl_helper();

private:
	std::shared_ptr<ssl_heaper_impl> impl;
};

#endif
