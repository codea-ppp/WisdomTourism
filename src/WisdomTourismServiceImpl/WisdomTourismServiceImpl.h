#ifndef WISDOM_TOURISM_SERVICE_IMPL_H_
#define WISDOM_TOURISM_SERVICE_IMPL_H_

#include <butil/logging.h>
#include <brpc/server.h>
#include <brpc/restful.h>
#include <brpc/controller.h>
#include <brpc/authenticator.h>
#include <brpc/ssl_options.h>

#include "google/http.pb.h"
#include "helper/ssl_helper/ssl_helper.h"

class WisdomTourismServiceImpl : public WisdomTourismService 
{
public:
    void login
		(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done);

    void logout
		(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done);

    void registe_admin
		(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done);

    void set_competence
		(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done);

    void set_location 
		(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done);

    void set_parkinglot
		(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done);

    void set_monitor
		(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done);

    void set_hotel
		(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done);

    void set_room
		(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done);

    void issue_ticket
		(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done);

    void search_ticket
		(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done);

    void tourist_checkin
		(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done);

    void tourist_checkout
		(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done);

    void tourist_track_search
		(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done);

    void registe_location
		(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done);

    void invite_monitor
		(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done);

    void car_checkin
		(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done);

    void car_checkout
		(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done);

    void car_track_search
		(google::protobuf::RpcController* cntl_base, const HttpRequest*, HttpResponse*, google::protobuf::Closure* done);

public:
    WisdomTourismServiceImpl();
    virtual ~WisdomTourismServiceImpl();

private:
	struct AuthArgsPack { std::string username, realm, nonce, uri, algorithm, cnonce, response, opaque; };

	int get_authenticator_args(const std::string* need_analyse, AuthArgsPack& args);

	const std::string give_me_token();
	void MD5ing_token(unsigned char token_md5[32], const std::string& token);

	void generate_nonce_opaque(unsigned char nonce[32], unsigned char opaque[32]);

	bool digest_auth(AuthArgsPack args_pack);
	bool bearer_auth(const std::string* authenticator, std::vector<int>& inerface_can_access);

private:
	ssl_helper _ssl_helper;
};

#endif 
