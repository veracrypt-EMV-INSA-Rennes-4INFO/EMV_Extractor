HEADERS = IccDataExtractor.h TLVParser.h

default: main

TLVParser.o: TLVParser.cpp $(HEADERS)
	g++  -o TLVParser.o -c TLVParser.cpp

IccDataExtractor.o: IccDataExtractor.cpp $(HEADERS)
	g++ -c IccDataExtractor.cpp -o IccDataExtractor.o -I/usr/include/PCSC/ -lpcsclite

main.o: main.cpp $(HEADERS)
	g++ -I/usr/include/PCSC/ -lpcsclite -c main.cpp -o main.o

main:	main.o IccDataExtractor.o TLVParser.o
	g++  main.o IccDataExtractor.o TLVParser.o -o main -I/usr/include/PCSC/ -lpcsclite

clean:
	-rm -f *.o main