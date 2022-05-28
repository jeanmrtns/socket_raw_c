prj=socket_raw

# .c files
C_SRC=$(wildcard ./src/*.c ./libs/*.c)

# .h files
H_SRC=$(wildcard ./includes/*.h)

# Object files
OBJ:=$(patsubst %.c,./objects/%.o,$(notdir $(C_SRC)))

# Compiler and linker
CC=gcc

# Flags for compiler
CC_FLAGS=-c	\
	-W		\
	-Wall	\
	-ansi	\
	-pedantic

# Command used at clean target
RM=rm -rf

# Compilation and linking

all: objFolder $(prj)

$(prj): $(OBJ)
	@echo 'Building binary using GCC linker: $@'
	@echo "---------------> $(OBJ)"
	$(CC) $^ -o $@
	@echo 'Finished building binary: $@'
	@echo ' '

./objects/%.o: ./src/%.c ./libs/%.c ./includes/%.h
	@echo 'Building target using GCC compiler: $<'
	$(CC) $< $(CC_FLAGS) -o $@
	@echo ' '

./objects/main.o: ./src/main.c $(H_SRC)
	@echo 'Building target using GCC compiler: $<'
	$(CC) $< $(CC_FLAGS) -o $@
	@echo ' '

./objects/socket_raw.o: ./libs/socket_raw.c
	@echo 'Building target using GCC compiler: $<'
	$(CC) $< $(CC_FLAGS) -o $@
	@echo ' '

objFolder:
	@mkdir -p objects

clean:
	@find . -name "*.o" -exec $(RM) {} \;
	@rm -rf objects *~
	@rm $(prj)

.PHONY: all clean