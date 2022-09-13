CC := clang

# ifeq ($(DEBUG),1)
# 	CFLAGS := -Wall -O0 
# else
# 	CFLAGS := -Wall -O1 
# endif

LDFLAGS := -lpcap -ljson-c  -fsanitize=address -Wall -g  #-pthread -l

# -fsanitize=address

run: main.o hashtable.o
	$(CC) -o run hashtable.o main.o  $(LDFLAGS)
	
main.o: main.c
	$(CC) $(CFLAGS) -c main.c $(LDFLAGS)
hashtable.o: hashtable.c hashtable.h
	$(CC) $(CFLAGS) -c hashtable.c $(LDFLAGS)
# connection.o: connection.c connection.h
# 	$(CC) $(CFLAGS) -c connection.c $(LDFLAGS)
# transaction.o: transaction.c transaction.h
# 	$(CC) $(CFLAGS) -c transaction.c $(LDFLAGS)


clear:
	rm  -f *.o run log.txt
	