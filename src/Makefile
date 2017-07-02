c3h-client : auth.o main.o md5.o adapter.o
	$(CC) $(LDFLAGS) auth.o main.o md5.o adapter.o -lpcap -o c3h-client

auth.o : auth.c
	$(CC) $(CFLAGS) -DNDEBUG -Wall -g -O2 -c auth.c

main.o : main.c
	$(CC) $(CFLAGS) -DNDEBUG -Wall -g -O2 -c main.c

md5.o : md5.c
	$(CC) $(CFLAGS) -DNDEBUG -Wall -g -O2 -c md5.c

adapter.o : adapter.c
	$(CC) $(CFLAGS) -DNDEBUG -Wall -g -O2 -c adapter.c

clean :
	rm *.o c3h-client
