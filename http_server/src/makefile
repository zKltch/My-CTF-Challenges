all:server.c 
	gcc server.c -o ../share/server -fstack-protector-all -Wl,-z,relro,-z,now
clean:
	rm -rf server
