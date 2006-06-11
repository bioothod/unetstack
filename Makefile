#KDIR	:= /lib/modules/$(shell uname -r)/build
KDIR	:= /home/s0mbre/aWork/git/linux-2.6/linux-2.6.net
PWD	:= $(shell pwd)
CC	:= gcc

CFLAGS	:= -I$(KDIR)/include -W -Wall -DDEBUG -g
LDFLAGS := -lc

OBJS := tcp.o udp.o ip.o eth.o netchannel.o packet.o ncbuff.o route.o
TARGETS	:= stack

all: $(OBJS) $(TARGETS)
	@echo "Compilation has been successfully finished."

stack: $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@

%.o:$(patsubst %.o,%.c,$<)
	$(CC) $(CFLAGS) $(patsubst %.o,%.c,$@) -c -o $@

clean:
	rm -f *.o *~ $(TARGETS) $(LIB_OBJS)

%:$(patsubst %,%.c,$<)
%.o:$(patsubst %.o,%.c,$<)
