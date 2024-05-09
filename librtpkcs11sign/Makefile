TARGET = librtpkcs11sign.so
SRCS = sign.c
HEADERS = sign.h
LDFLAGS_LOCAL = -fPIC -shared -ldl
export LD_LIBRARY_PATH = .

.PHONY: all clean test_sign

all: $(TARGET)
$(TARGET): $(SRCS) $(HEADERS)
	$(CC) $(SRCS) $(LDFLAGS_LOCAL) -o $(TARGET)

test: test_sign.c
	$(CC) test_sign.c -L. -lrtpkcs11sign -o test_sign
	./test_sign

clean:
	rm -rf test_sign $(TARGET)
