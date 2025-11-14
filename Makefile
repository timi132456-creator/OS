CC = gcc
TARGET = dkuware
OBJS = dkuware.o crypto.o utils.o

CFLAGS = -Wall -g
LDFLAGS = -pthread -lcrypto -lssl

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)