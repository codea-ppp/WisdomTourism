o_directionaries = \
	$(src_path)/google/ \
	$(src_path)/WisdomTourismServiceImpl

links = \
	gflags \
	leveldb \
	brpc \
	protobuf \
	helper \
	mariadb \
	crypto \
	base64 \
	jsoncpp

link_paths = \
	$(src_path)/helper

objs 	= $(shell fd -I '.*\.o' $(o_directionaries)) main.o
target 	= WisdomTourismService.out

.PHONY : all, clean

all : $(target)

clean :
	rm -f $(target) main.o

$(target) : $(objs)
	$(cc) $(cc_flags) -o $@ $(objs) $(foreach link, $(links), -l$(link)) $(foreach linkpath, $(link_paths), -L$(linkpath))

%.o : %.cpp
	$(cc) $(cc_flags) -o $@ -c $<