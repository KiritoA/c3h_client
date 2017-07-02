TARGET = c3h-client
BIN_DIR = /usr/sbin/
INCLUDES = 
LIBS = -lpcap

UP_CC := gcc
RM := rm -rf

C_SOURCES       = $(wildcard *.c)
C_OBJS = $(patsubst %.c, %.o, $(C_SOURCES))

CFLAGS = -DNDEBUG -Wall -g
CFLAGS += -O2
# ------------  generate the names of the object files  ------------------------
OBJECTS         = $(addsuffix .o,$(BASENAMES))

# ------------  generate the names of the hidden prerequisite files  -----------
PREREQUISITES   = $(addprefix .,$(addsuffix .d,$(BASENAMES)))

# ------------  make the executable (the default goal)  ------------------------
%.o:%.c
	$(UP_CC) -c $(CFLAGS) $<$ $(CCFLAGS)

$(TARGET): $(CPP_OBJS) $(C_OBJS)
	$(CXX)$(LINKFLAGS) -o $(TARGET) $^ $(LIBS)

all:$(TARGET)

clean:
	$(RM) $(CPP_OBJS) $(C_OBJS)
	$(RM) $(TARGET)

install: $(TARGET)
	cp $(TARGET) $(BIN_DIR)

uninstall:
	rm -f $(BIN_DIR)/$(TARGET)

rebuild: clean all

# ==============================================================================
# vim: set tabstop=2: set shiftwidth=2:
