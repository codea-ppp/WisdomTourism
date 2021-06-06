#ifndef INERFACE_ID_H_
#define INERFACE_ID_H_

enum inerface_id
{
	login											= 101,
	logout											= 102,			

	registe_admin									= 201,
	set_competence									= 202,
	set_location									= 203,
	set_parkinglot									= 204,
	set_monitor										= 205,
	set_hotel										= 206,
	set_room										= 207,

	issue_ticket									= 301,
	search_ticket									= 302,

	tourist_checkin									= 401,
	tourist_checkout								= 402,
	tourist_track_search							= 403,

	registe_location								= 501,
	invite_monitor									= 502,

	car_checkin										= 601,
	car_checkout									= 602,
	car_track_search								= 603,
};

#endif 
