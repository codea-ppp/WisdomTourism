objs = $(shell fd -I '.*\.o')
target = libhelper.so

.PHONY : all, clean

all : $(target)

clean :
	rm -f $(target)

$(target) : $(objs)
	$(cc) $(cc_flags) --shared -o $@ $(objs)