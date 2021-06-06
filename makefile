export project_path = $(shell pwd)
export src_path		= $(project_path)/src

export cc 		= g++
export cc_flags	= -O3 -Wall -I$(src_path)
export cc_proto	= protoc

directionary_to_compile = \
	$(src_path)/helper/ssl_helper/ \
	$(src_path)/helper/sql_helper/ \
	$(src_path)/helper/ \
	$(src_path)/google/ \
	$(src_path)/WisdomTourismServiceImpl \
	$(src_path)

.PHONY : all, clean

all :
	@$(foreach dir, $(directionary_to_compile), $(MAKE) -C $(dir);)

clean :
	@$(foreach dir, $(directionary_to_compile), $(MAKE) -C $(dir) clean;)