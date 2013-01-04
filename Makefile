OBJ=logger_test.o logger.o
CFLAGS?=-g -Wall -pedantic
LDFLAGS+=-lpthread

all: logger-test

clean:
	rm -f logger-test
	rm -f $(OBJ)

logger-test : $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

%.o : %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@
