HEADERS = IccExtractor.h Tlv.h

default:	main

Tlv.o: Tlv.c $(HEADERS)
	g++  -o Tlv.o -c Tlv.c

IccDataExtractor.o: IccDataExtractor.cpp $(HEADERS)
	g++ -c IccDataExtractor.cpp -o IccDataExtractor.o -I/usr/include/PCSC/ -lpcsclite

main.o: main.cpp $(HEADERS)
	g++ -I/usr/include/PCSC/ -lpcsclite -c main.cpp -o main.o

main:	main.o IccDataExtractor.o Tlv.o
	g++  main.o IccDataExtractor.o Tlv.o -o main -I/usr/include/PCSC/ -lpcsclite

clean:
	-rm -f *.o main