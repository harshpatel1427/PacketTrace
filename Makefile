mydump: mydump.c functionUtil.c printHeader.c
	gcc -o mydump mydump.c functionUtil.c printHeader.c -lpcap -I.
clean: 
	rm -rf mydump
