#include "IccExtractor.h"


int main(int argc, char *argv[])
{
    fprintf(stderr,"EstablishRSContext\n");
    EstablishRSContext();
    fprintf(stderr,"GetReaders");
    GetReaders();
    int reader_nb = 0; // it's hardcoded for now but it should be a parameter with veracrypt
    fprintf(stderr,"ConnectCard");
    ConnectCard(reader_nb);
    fprintf(stderr,"StatusCard");
    StatusCard();

    // we create a unsigned char array to store the data and then convert it to a vector to pass it to the keyfileData
    unsigned char ICC_DATA[1024]; // 1024 bytes should be enough to store the issuer and icc pk certificate of one app + CPCL
    for (int i = 0; i < 1024; i++) {
        ICC_DATA[i] = 0;
    }

    int ICC_DATA_SIZE = 0;
    fprintf(stderr,"GettingAllCerts");
    GettingAllCerts(ICC_DATA, &ICC_DATA_SIZE);

    // in the veracrypt code, we have to convert the unsigned char array to a vector with the returned length
    printf("All the data has been extracted ! \n");
    printByteArray(ICC_DATA, ICC_DATA_SIZE);
    
    fprintf(stderr,"FinishClean");
    FinishClean();
    fprintf(stderr,"EMV Part DONE!!!");
}