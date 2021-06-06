#include <vector>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <base64.h>

#include "helper/sql_helper/sql_helper.h"
#include "helper/sql_helper/sql_helper_impl.h"
#include "WisdomTourismServiceImpl.h"
#include "inerface_id.h"

int WisdomTourismServiceImpl::get_authenticator_args(const std::string* need_analyse, AuthArgsPack& args)
{
	std::string::size_type value_begin	= 0; 
	std::string::size_type value_end	= 0; 

#define SEARCH_SUBSTR(k, v)													\
	value_begin = need_analyse->find(k, value_end);							\
	if (std::string::npos == value_begin)									\
	{																		\
		printf("failed to search %s begin\n", k);							\
		return -1;															\
	}																		\
																			\
	value_begin = need_analyse->find_first_of("\"", value_begin);			\
	value_end	= need_analyse->find_first_of("\"", value_begin + 1);		\
																			\
	if (std::string::npos == value_end)										\
	{																		\
		printf("failed to search %s end\n", k);								\
		return -1;															\
	}																		\
																			\
	v = need_analyse->substr(value_begin + 1, value_end - value_begin - 1);

	SEARCH_SUBSTR("username=\"",	args.username);
	SEARCH_SUBSTR("realm=\"",		args.realm);
	SEARCH_SUBSTR("nonce=\"",		args.nonce);
	SEARCH_SUBSTR("uri=\"",			args.uri);
	SEARCH_SUBSTR("algorithm=\"",	args.algorithm);
	SEARCH_SUBSTR("cnonce=\"",		args.cnonce);
	SEARCH_SUBSTR("response=\"",	args.response);
	SEARCH_SUBSTR("opaque=\"",		args.opaque);
#undef SEARCH_SUBSTR

	return 0;
}

const std::string WisdomTourismServiceImpl::give_me_token()
{
	static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	srand((unsigned)time(NULL) * getpid());

	std::string token;
	token.reserve(4096);

	for (int i = 0; i < 4096; ++i)
	{
		token += alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	return token;
}

void WisdomTourismServiceImpl::MD5ing_token(unsigned char token_md5[32], const std::string& token)
{
	unsigned char token_md5_raw[17]; token_md5[16] = '\0';

	_ssl_helper.get_md5_hash(token_md5_raw, (unsigned char*)token.c_str(), token.size());
	_ssl_helper.MD5_cooking(token_md5_raw, token_md5);
}

void WisdomTourismServiceImpl::generate_nonce_opaque(unsigned char nonce[32], unsigned char opaque[32])
{
	std::string	random				= boost::uuids::to_string(boost::uuids::random_generator()());
	const unsigned char* seed		= (unsigned char*)random.c_str();
	size_t size						= random.size();

	unsigned char nonce_raw[17]		= { 0 }; 
	unsigned char opaque_raw[17]	= { 0 }; 

	_ssl_helper.get_md5_hash(nonce_raw, seed, size);
	_ssl_helper.cooking(nonce_raw, nonce, 20);

	_ssl_helper.get_md5_hash(opaque_raw, seed, size);
	_ssl_helper.cooking(opaque_raw, opaque, 16);
}

bool WisdomTourismServiceImpl::digest_auth(AuthArgsPack args_pack)
{
	unsigned char md5_buffer_raw[17]	= { 0 };
	unsigned char md5_buffer_cook[33]	= { 0 };
	unsigned char md5_password_cook[33] = { 0 };

	if (!sql_helper::mariadb_helper::search_user_password(args_pack.username.c_str(), md5_password_cook))
	{
		LOG(ERROR) << "Failed to search " << args_pack.username << "'s password'";
		return false;
	}

	std::string urp((char*)md5_password_cook);
	urp.append(":").append(args_pack.nonce).append(":").append(args_pack.cnonce);

	_ssl_helper.get_md5_hash(md5_buffer_raw, (unsigned char*)urp.c_str(), urp.size());
	_ssl_helper.MD5_cooking(md5_buffer_raw, md5_buffer_cook);
	std::string HA1((const char*)md5_buffer_cook);

	std::string mu("GET:");
	mu.append(args_pack.uri);

	_ssl_helper.get_md5_hash(md5_buffer_raw, (unsigned char*)mu.c_str(), mu.size());
	_ssl_helper.MD5_cooking(md5_buffer_raw, md5_buffer_cook);
	std::string HA2((const char*)md5_buffer_cook);

	HA1.append(":").append(args_pack.nonce).append(":").append("00000001").append(":").append(args_pack.cnonce).append(":").append("auth").append(":").append(HA2);

	_ssl_helper.get_md5_hash(md5_buffer_raw, (unsigned char*)HA1.c_str(), HA1.size());
	_ssl_helper.MD5_cooking(md5_buffer_raw, md5_buffer_cook);

	if (args_pack.response.size() != strlen((const char*)md5_buffer_cook))
		return false;

	bool is_good = false;
	for (unsigned int i = 0; i < args_pack.response.size(); ++i)
	{
		is_good |= !(md5_buffer_cook[i] == args_pack.response[i]);
	}

	return !is_good;
}

bool WisdomTourismServiceImpl::bearer_auth(const std::string* authenticator, std::vector<int>& inerface_can_access)
{
	char token[4097]; token[4096] = '\0';
	if (!sscanf(authenticator->c_str(), "Bearer %s", token) || strlen(token) != 4096)
		return false;

	unsigned char token_md5[33]; token_md5[32] = '\0';
	MD5ing_token(token_md5, token);

	return sql_helper::mariadb_helper::search_user_competence((const char*)token_md5, inerface_can_access);
}

WisdomTourismServiceImpl::WisdomTourismServiceImpl()
{
}

WisdomTourismServiceImpl::~WisdomTourismServiceImpl()
{
}

void WisdomTourismServiceImpl::login(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done) 
{
	brpc::ClosureGuard	done_guard(done);
	brpc::Controller*	cntl = static_cast<brpc::Controller*>(cntl_base);

	const std::string* authenticator = cntl->http_request().GetHeader("Authorization");
	if (nullptr == authenticator)
	{
		unsigned char nonce[33]		= { 0 };
		unsigned char opaque[33]	= { 0 };
		generate_nonce_opaque(nonce, opaque);

		char buffer[4096] = { 0 };
		snprintf(buffer, 4096, "Digest realm=\"codea-ppp\", qop=\"auth\", nonce=\"%s\", opaque=\"%s\"", nonce, opaque);

		cntl->http_response().set_status_code(brpc::HTTP_STATUS_UNAUTHORIZED);
		cntl->http_response().SetHeader("WWW-Authenticate", buffer);

		return ;
	}

	AuthArgsPack args_pack; 
	if (get_authenticator_args(authenticator, args_pack))
	{
		cntl->http_response().set_status_code(brpc::HTTP_STATUS_BAD_REQUEST);
		return ;
	}
	else if (!digest_auth(args_pack))
	{
		cntl->http_response().set_status_code(brpc::HTTP_STATUS_BAD_REQUEST);
		return ;
	}

	std::string token = give_me_token();

	unsigned char token_md5[33]; token_md5[32] = { 0 };

	MD5ing_token(token_md5, token);

	if (!sql_helper::mariadb_helper::insert_user_token(args_pack.username.c_str(), (const char*)token_md5))
	{
		cntl->http_response().set_status_code(brpc::HTTP_STATUS_BAD_REQUEST);
		return ;
	}
	else
	{
		cntl->http_response().set_status_code(brpc::HTTP_STATUS_OK);
		cntl->response_attachment().clear();
		cntl->response_attachment().append("{ \"token\": \"");
		cntl->response_attachment().append(token);
		cntl->response_attachment().append("\" }");
	}
}

void WisdomTourismServiceImpl::logout(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done) 
{
	LOG(INFO) << __func__ << " called";

	brpc::ClosureGuard done_guard(done);
	brpc::Controller* cntl = static_cast<brpc::Controller*>(cntl_base);

	const std::string* authenticator = cntl->http_request().GetHeader("Authorization");
	if (nullptr == authenticator)
	{
		cntl->http_response().set_status_code(brpc::HTTP_STATUS_BAD_REQUEST);
		return ;
	}

	char token[4097]; token[4096] = '\0';
	if (!sscanf(authenticator->c_str(), "Bearer %s", token) || strlen(token) != 4096)
	{
		cntl->http_response().set_status_code(brpc::HTTP_STATUS_BAD_REQUEST);
		return ;
	}

	unsigned char token_md5[33]; token_md5[32] = '\0';
	MD5ing_token(token_md5, token);

	if (!sql_helper::mariadb_helper::delete_user_token((const char*)token_md5))
	{
		cntl->http_response().set_status_code(brpc::HTTP_STATUS_BAD_REQUEST);
		return ;
	}
}

void WisdomTourismServiceImpl::registe_admin(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done) 
{
	LOG(INFO) << __func__ << " called";

	brpc::ClosureGuard done_guard(done);
	brpc::Controller* cntl = static_cast<brpc::Controller*>(cntl_base);

	const std::string* authenticator = cntl->http_request().GetHeader("Authorization");
	LOG(INFO) << *authenticator;
	LOG(INFO) << cntl->http_request().uri().query();
}

void WisdomTourismServiceImpl::set_competence(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done) 
{
	LOG(INFO) << __func__ << " called";

	brpc::ClosureGuard done_guard(done);
	brpc::Controller* cntl = static_cast<brpc::Controller*>(cntl_base);

	const std::string* authenticator = cntl->http_request().GetHeader("Authorization");
	LOG(INFO) << *authenticator;
	LOG(INFO) << cntl->http_request().uri().query();
}

void WisdomTourismServiceImpl::set_location(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done) 
{
	LOG(INFO) << __func__ << " called";

	brpc::ClosureGuard done_guard(done);
	brpc::Controller* cntl = static_cast<brpc::Controller*>(cntl_base);

	const std::string* authenticator = cntl->http_request().GetHeader("Authorization");
	LOG(INFO) << *authenticator;
	LOG(INFO) << cntl->http_request().uri().query();
}

void WisdomTourismServiceImpl::set_parkinglot(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done) 
{
	LOG(INFO) << __func__ << " called";

	brpc::ClosureGuard done_guard(done);
	brpc::Controller* cntl = static_cast<brpc::Controller*>(cntl_base);

	const std::string* authenticator = cntl->http_request().GetHeader("Authorization");
	LOG(INFO) << *authenticator;
	LOG(INFO) << cntl->http_request().uri().query();
}

void WisdomTourismServiceImpl::set_monitor(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done) 
{
	LOG(INFO) << __func__ << " called";

	brpc::ClosureGuard done_guard(done);
	brpc::Controller* cntl = static_cast<brpc::Controller*>(cntl_base);

	const std::string* authenticator = cntl->http_request().GetHeader("Authorization");
	LOG(INFO) << *authenticator;
	LOG(INFO) << cntl->http_request().uri().query();
}

void WisdomTourismServiceImpl::set_hotel(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done) 
{
	LOG(INFO) << __func__ << " called";

	brpc::ClosureGuard done_guard(done);
	brpc::Controller* cntl = static_cast<brpc::Controller*>(cntl_base);

	const std::string* authenticator = cntl->http_request().GetHeader("Authorization");
	LOG(INFO) << *authenticator;
	LOG(INFO) << cntl->http_request().uri().query();
}

void WisdomTourismServiceImpl::set_room(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done) 
{
	LOG(INFO) << __func__ << " called";

	brpc::ClosureGuard done_guard(done);
	brpc::Controller* cntl = static_cast<brpc::Controller*>(cntl_base);

	const std::string* authenticator = cntl->http_request().GetHeader("Authorization");
	LOG(INFO) << *authenticator;
	LOG(INFO) << cntl->http_request().uri().query();
}

void WisdomTourismServiceImpl::issue_ticket(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done) 
{
	LOG(INFO) << __func__ << " called";

	brpc::ClosureGuard done_guard(done);
	brpc::Controller* cntl = static_cast<brpc::Controller*>(cntl_base);

	const std::string* authenticator = cntl->http_request().GetHeader("Authorization");
	LOG(INFO) << *authenticator;
	LOG(INFO) << cntl->http_request().uri().query();
}

void WisdomTourismServiceImpl::search_ticket(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done) 
{
	LOG(INFO) << __func__ << " called";

	brpc::ClosureGuard done_guard(done);
	brpc::Controller* cntl = static_cast<brpc::Controller*>(cntl_base);

	const std::string* authenticator = cntl->http_request().GetHeader("Authorization");
	LOG(INFO) << *authenticator;
	LOG(INFO) << cntl->http_request().uri().query();
}

void WisdomTourismServiceImpl::tourist_checkin(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done) 
{
	LOG(INFO) << __func__ << " called";

	brpc::ClosureGuard done_guard(done);
	brpc::Controller* cntl = static_cast<brpc::Controller*>(cntl_base);

	const std::string* authenticator = cntl->http_request().GetHeader("Authorization");
	LOG(INFO) << *authenticator;
	LOG(INFO) << cntl->http_request().uri().query();
}

void WisdomTourismServiceImpl::tourist_checkout(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done) 
{
	LOG(INFO) << __func__ << " called";

	brpc::ClosureGuard done_guard(done);
	brpc::Controller* cntl = static_cast<brpc::Controller*>(cntl_base);

	const std::string* authenticator = cntl->http_request().GetHeader("Authorization");
	LOG(INFO) << *authenticator;
	LOG(INFO) << cntl->http_request().uri().query();
}

void WisdomTourismServiceImpl::tourist_track_search(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done) 
{
	LOG(INFO) << __func__ << " called";

	brpc::ClosureGuard done_guard(done);
	brpc::Controller* cntl = static_cast<brpc::Controller*>(cntl_base);

	const std::string* authenticator = cntl->http_request().GetHeader("Authorization");
	LOG(INFO) << *authenticator;
	LOG(INFO) << cntl->http_request().uri().query();
}

void WisdomTourismServiceImpl::registe_location(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done) 
{
	LOG(INFO) << __func__ << " called";

	brpc::ClosureGuard done_guard(done);
	brpc::Controller* cntl = static_cast<brpc::Controller*>(cntl_base);

	const std::string* authenticator = cntl->http_request().GetHeader("Authorization");
	LOG(INFO) << *authenticator;
	LOG(INFO) << cntl->http_request().uri().query();
}

void WisdomTourismServiceImpl::invite_monitor(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done) 
{
	LOG(INFO) << __func__ << " called";

	brpc::ClosureGuard done_guard(done);
	brpc::Controller* cntl = static_cast<brpc::Controller*>(cntl_base);

	const std::string* authenticator = cntl->http_request().GetHeader("Authorization");
	LOG(INFO) << *authenticator;
	LOG(INFO) << cntl->http_request().uri().query();
}

void WisdomTourismServiceImpl::car_checkin(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done) 
{
	LOG(INFO) << __func__ << " called";

	brpc::ClosureGuard done_guard(done);
	brpc::Controller* cntl = static_cast<brpc::Controller*>(cntl_base);

	const std::string* authenticator = cntl->http_request().GetHeader("Authorization");
	LOG(INFO) << *authenticator;
	LOG(INFO) << cntl->http_request().uri().query();
}

void WisdomTourismServiceImpl::car_checkout(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done) 
{
	LOG(INFO) << __func__ << " called";

	brpc::ClosureGuard done_guard(done);
	brpc::Controller* cntl = static_cast<brpc::Controller*>(cntl_base);

	const std::string* authenticator = cntl->http_request().GetHeader("Authorization");
	LOG(INFO) << *authenticator;
	LOG(INFO) << cntl->http_request().uri().query();
}

void WisdomTourismServiceImpl::car_track_search(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done) 
{
	LOG(INFO) << __func__ << " called";

	brpc::ClosureGuard done_guard(done);
	brpc::Controller* cntl = static_cast<brpc::Controller*>(cntl_base);

	const std::string* authenticator = cntl->http_request().GetHeader("Authorization");
	LOG(INFO) << *authenticator;
	LOG(INFO) << cntl->http_request().uri().query();
}
