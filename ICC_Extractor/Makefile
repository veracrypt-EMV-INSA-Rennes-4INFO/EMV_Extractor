HEADERS = IccExtractor.h Tlv.h

default:	main

Tlv.o: Tlv.c $(HEADERS)
	gcc -o Tlv.o -c Tlv.c

IccExtractor.o: IccExtractor.c $(HEADERS)
	gcc -o IccExtractor.o -c IccExtractor.c

main.o: main.c $(HEADERS)
	gcc -I/usr/include/PCSC/ -lpcsclite -c main.c -o main.o

main:	main.o IccExtractor.o Tlv.o
	gcc main.o IccExtractor.o Tlv.o -o main -I/usr/include/PCSC/ -lpcsclite

clean:
	-rm -f *.o main