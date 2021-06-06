#include <algorithm>
#include <iostream>
#include <fstream>

#include <json/json.h>
#include <gflags/gflags.h>
#include <json/reader.h>
#include <json/value.h>

#include "google/gflags_define.h"
#include "helper/sql_helper/sql_helper.h"
#include "WisdomTourismServiceImpl/WisdomTourismServiceImpl.h"

int main(int argc, char* argv[]) 
{
	GFLAGS_NAMESPACE::ParseCommandLineFlags(&argc, &argv, true);

    brpc::Server server;
    WisdomTourismServiceImpl wisdom_tourism_svc;
    
	if (0 != server.AddService(
				&wisdom_tourism_svc, 
				brpc::SERVER_DOESNT_OWN_SERVICE, 
				"/login					==> login," 
				"/logout				==> logout," 
				"/registe_admin			==> registe_admin," 
				"/set_competence		==> set_competence," 
				"/set_location			==> set_location," 
				"/set_parkinglot		==> set_parkinglot," 
				"/set_monitor			==> set_monitor," 
				"/set_hotel				==> set_hotel," 
				"/set_room				==> set_room," 
				"/issue_ticket			==> issue_ticket," 
                "/search_ticket			==> search_ticket," 
				"/tourist_checkin		==> tourist_checkin," 
				"/tourist_checkout		==> tourist_checkout," 
				"/tourist_track_search	==> tourist_track_search," 
				"/registe_location		==> registe_location," 
				"/invite_monitor		==> invite_monitor," 
				"/car_checkin			==> car_checkin," 
				"/car_checkout			==> car_checkout," 
				"/car_track_search		==> car_track_search," 
	)) {
        LOG(ERROR) << "Fail to add wisdom_tourism_svc";
        return -1;
    }

#define CLOSE_CONFIG_FILES fclose(private_key); fclose(cert); fclose(config);
	FILE* cert = fopen(FLAGS_certificate.c_str(), "r");
	if (nullptr == cert)
	{
		LOG(ERROR) << "Failed to load " << FLAGS_certificate;
		return -1;
	}

	FILE* private_key = fopen(FLAGS_private_key.c_str(), "r");
	if (nullptr == private_key)
	{
		fclose(cert);

		LOG(ERROR) << "Failed to load " << FLAGS_private_key;
		return -1;
	}

	FILE* config = fopen(FLAGS_config_path.c_str(), "r");
	if (nullptr == config)
	{
		fclose(private_key);
		fclose(cert);

		LOG(ERROR) << "Failed to load " << FLAGS_config_path;
		return -1;
	}
	
	brpc::CertInfo cert_info;

	char buffer[4096] = { 0 };
	std::fread(buffer, sizeof(char), 4096, cert);
	cert_info.certificate = buffer;

	memset(buffer, 0, 4096);
	std::fread(buffer, sizeof(char), 4096, private_key);
	cert_info.private_key = buffer;

	memset(buffer, 0, 4096);
	size_t size = std::fread(buffer, sizeof(char), 4096, config);

    brpc::ServerOptions options;
    options.idle_timeout_sec = FLAGS_idle_timeout_s;
	options.mutable_ssl_options()->default_cert = cert_info;

	Json::Value	root;
	Json::CharReaderBuilder	reader_builder;
	Json::CharReader* reader = reader_builder.newCharReader();
	reader->parse(buffer, buffer + size, &root, nullptr);

	if (!root.isMember("database_config") || !root["database_config"].isObject())
	{
		LOG(ERROR) << "config file [database_config] bad";
		CLOSE_CONFIG_FILES 
		return -1;
	}

	Json::Value database_config = root["database_config"];
	if (!database_config.isMember("database_username") || !database_config["database_username"].isString())
	{
		LOG(ERROR) << "config file [database_username] bad";
		CLOSE_CONFIG_FILES 
		return -1;
	}
	if (!database_config.isMember("database_password") || !database_config["database_password"].isString())
	{
		LOG(ERROR) << "config file [database_password] bad";
		CLOSE_CONFIG_FILES 
		return -1;
	}
	if (!database_config.isMember("database_selected") || !database_config["database_selected"].isString())
	{
		LOG(ERROR) << "config file [database_selected] bad";
		CLOSE_CONFIG_FILES 
		return -1;
	}
	if (!database_config.isMember("database_ip") || !database_config["database_ip"].isString())
	{
		LOG(ERROR) << "config file [database_ip] bad";
		CLOSE_CONFIG_FILES 
		return -1;
	}
	if (!database_config.isMember("database_port") || !database_config["database_port"].isUInt())
	{
		LOG(ERROR) << "config file [database_port] bad";
		CLOSE_CONFIG_FILES 
		return -1;
	}
	if (!database_config.isMember("database_sock") || !database_config["database_sock"].isString())
	{
		LOG(ERROR) << "config file [database_sock] bad";
		CLOSE_CONFIG_FILES 
		return -1;
	}

	if (!sql_helper::mariadb_helper::connect_to(
		database_config["database_ip"].asString().c_str(),		 database_config["database_port"].asUInt(),
		database_config["database_username"].asString().c_str(), database_config["database_password"].asString().c_str(),
		database_config["database_selected"].asString().c_str(), database_config["database_sock"].asString().c_str()
	)) {
		LOG(INFO) << "Failed to connect database";
		CLOSE_CONFIG_FILES 
		return -1;
	}

    if (server.Start(FLAGS_port, &options) != 0) 
	{
        LOG(ERROR) << "Fail to start HttpServer";
        return -1;
    }

    server.RunUntilAskedToQuit();
    return 0;
}
