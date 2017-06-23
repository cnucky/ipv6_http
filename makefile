obj-m		:= ipv6_http.o
KERNELDIR	:= /lib/modules/$(shell uname -r)/build/
PWD 		:= $(shell pwd)

all:
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	rm -rf  .*.ko.cmd *.mod.o.cmd  .*.ko.unsigned.cmd .*.o.cmd .tmp_versions/ 
	rm -f  *.ko.unsigned *.mod.c *.mod.o *.o  modules.order  Module.symvers
