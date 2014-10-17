CC=$(CROSS_COMPILE)gcc
STRIP=$(CROSS_COMPILE)strip

TARGET_1=macscan
TARGET_1_OBJS=macscan.o

all : $(TARGET_1)

$(TARGET_1):$(TARGET_1_OBJS)
	$(CC) $(CFLAGS) -o $(TARGET_1) $(TARGET_1_OBJS)
	$(STRIP) $(TARGET_1)

clean:
	rm -rf *.o $(TARGET_1)
