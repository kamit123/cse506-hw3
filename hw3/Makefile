obj-m += sys_submitjob.o
sys_submitjob-objs := util.o xpress.o concat.o checksum.o xcrypt.o submitjob.o 

all: util xpress concat xcrypt submitjob xhw3 demo1 demo2 demo3

util:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

xpress:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

concat:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

checksum:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

xcrypt:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

submitjob:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

xhw3:
	gcc -Wall -Werror xhw3.c -o xhw3 -lssl -pthread

demo1:
	gcc -Wall -Werror demo1.c -o demo1 -lssl

demo2:
	gcc -Wall -Werror demo2.c -o demo2 -lssl

demo3:
	gcc -Wall -Werror demo3.c -o demo3 -lssl -pthread
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f xhw3 demo1 demo2 demo3
