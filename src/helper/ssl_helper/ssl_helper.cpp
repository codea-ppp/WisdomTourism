#include "ssl_helper.h"
#include "ssl_helper_impl.h"

void ssl_helper::get_md5_hash(unsigned char dst[16], const unsigned char* src, size_t size) 
{
	impl->get_md5_hash(dst, src, size);
}

void ssl_helper::cooking(unsigned char* raw, unsigned char* cook, int size)
{
	impl->cooking(raw, cook, size);
}

void ssl_helper::rawing(unsigned char* raw, unsigned char* cook, int size)
{
	impl->rawing(raw, cook, size);
}

void ssl_helper::MD5_cooking(unsigned char raw[16], unsigned char cook[32])
{
	impl->cooking(raw, cook, 16);
}

void ssl_helper::MD5_rawing(unsigned char raw[16], unsigned char cook[32])
{
	impl->rawing(raw, cook, 16);
}

ssl_helper::ssl_helper()
{
	impl = std::make_shared<ssl_heaper_impl>();
}

ssl_helper::~ssl_helper()
{
}
