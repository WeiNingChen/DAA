#file name
TARGET=myDAA
#compliler
CC=g++
#library path
LIB_PATH=lib
#include path
INCLUDE_PATH=include
#source path
SOURCE_PATH=src
#library name
ALL_LIB=libentity.a libutil.a
ENTITY_OBJS=issuer.o tpm.o host.o verifier.o protocol.o
UTIL_OBJS=util.o sha1.o myString.o

#LIBPKS  = protocol entity util


target: main.o $(ALL_LIB)
	@echo ">building myTest..."
	@$(CC) $< $(ALL_LIB) -o $(TARGET) -lgmp -lgmpxx -lstdc++
	@-cp $(ALL_LIB) $(LIB_PATH)
	@-rm -f $(ALL_LIB) $(ENTITY_OBJS) $(UTIL_OBJS) main.o

main.o: src/main/main.cpp
	@echo ">compiling: main.cpp..."	
	@$(CC) -I$(INCLUDE_PATH) -c -Wall $< -lgmp -lgmpxx -lstdc++
:
all:$(ALL_LIB)

libentity.a: $(ENTITY_OBJS)
	@echo "Building libentity.a..."	
	@ar rcs $@ $(ENTITY_OBJS)
libutil.a: $(UTIL_OBJS)
	@echo "Building libutil.a..."	
	@ar rcs $@ $(UTIL_OBJS)

issuer.o: $(SOURCE_PATH)/entity/issuer.cpp
	@echo ">compiling: issuer.cpp..."
	@$(CC) -I$(INCLUDE_PATH) -c -Wall -g $< -lgmp -lgmpxx
tpm.o: $(SOURCE_PATH)/entity/tpm.cpp
	@echo ">compiling: tpm.cpp..."	
	@$(CC) -I$(INCLUDE_PATH) -c -Wall -g $< -lgmp -lgmpxx
host.o: $(SOURCE_PATH)/entity/host.cpp
	@echo ">compiling: host.cpp..."
	@$(CC) -I$(INCLUDE_PATH) -c -Wall -g $< -lgmp -lgmpxx
verifier.o: $(SOURCE_PATH)/entity/verifier.cpp
	@echo ">compiling: verifier.cpp..."
	@$(CC) -I$(INCLUDE_PATH) -c -Wall -g $< -lgmp -lgmpxx
protocol.o: $(SOURCE_PATH)/protocol/protocol.cpp
	@echo ">compiling: protocol.cpp..."	
	@$(CC) -I$(INCLUDE_PATH) -c -Wall -g $< -lgmp -lgmpxx
util.o: $(SOURCE_PATH)/util/util.cpp
	@echo ">compiling: util.cpp..."	
	@$(CC) -I$(INCLUDE_PATH) -c -Wall -g $< -lgmp -lgmpxx
sha1.o: $(SOURCE_PATH)/util/sha1.cpp
	@echo ">compiling: sha1.cpp..."	
	@$(CC) -I$(INCLUDE_PATH) -c -Wall -g $< -lgmp -lgmpxx
myString.o: $(SOURCE_PATH)/util/myString.cpp
	@echo ">compiling: myString.cpp..."
	@$(CC) -I$(INCLUDE_PATH) -c -Wall -g $< -lgmp -lgmpxx

install: $(ALL_LIB)
	@-cp $(ALL_LIB) $(LIB_PATH)
	@-rm -f $(ALL_LIB) $(ENTITY_OBJS) $(UTIL_OBJS) main.o

clean:
#	@for lib in $(LIBPKGS); \
	do \
		echo "Cleaning $$lib..."; \
		cd $(SOURCE_PATH)/$$lib; make --no-print-directory PKGNAME=$$lib clean; \
		cd ../..; \
	done
	@echo "Cleaning protocol..."
	@-rm -f src/protocol.o
	@echo "Cleaning issuer..."
	@-rm -f src/entity/issuer.o
	@echo "Cleaning tpm..."
	@-rm -f src/entity/tpm.o
	@echo "Cleaning host..."
	@-rm -f src/entity/host.o
	@echo "Cleaning verifier..."
	@-rm -f src/entity/verifier.o
	@echo "Cleaning util..."
	@-rm -f src/util/util.o
	@-rm -f src/util/myString.o
	@-rm -f src/util/sha1.o
	@echo "Cleaning main..."
	@-rm -f src/main/main.o
	@echo "Removing $(LIB_PATH)..."
	@-rm -f lib/libentity.a
	@-rm -f lib/libutil.a
	@echo "Removing $(TARGET)..."
	@-rm -f bin/$(TARGET)
	@-rm -f $(TARGET)
