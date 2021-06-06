#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "ssl_helper.h"

class ssl_heaper_impl
{
public:
	void get_md5_hash(unsigned char dst[16], const unsigned char* src, size_t size);

	void cooking(unsigned char* raw, unsigned char* cook, int size);
	void rawing(unsigned char* raw, unsigned char* cook, int size);

	ssl_heaper_impl();
	~ssl_heaper_impl();

private:
	ssl_heaper_impl(const ssl_heaper_impl&)						= delete ;
	ssl_heaper_impl(const ssl_heaper_impl&&)					= delete ;
	const ssl_heaper_impl&	operator=(const ssl_heaper_impl&)	= delete ;
	const ssl_heaper_impl&& operator=(const ssl_heaper_impl&&)	= delete ;

	EVP_MD_CTX*		ctx;
	const EVP_MD*	MD5_t;
};
