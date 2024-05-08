TARGET = librtpks11sign.so
SRCS = sign.c
HEADERS = sign.h
LDFLAGS_LOCAL = -fPIC -shared -ldl

.PHONY: all

all: $(TARGET)
$(TARGET): $(SRCS) $(HEADERS)
	$(CC) $(SRCS) $(LDFLAGS_LOCAL) -o $(TARGET)

test: test_sign.c
	$(CC) test_sign.c -L. -lrtsign -o test_sign
