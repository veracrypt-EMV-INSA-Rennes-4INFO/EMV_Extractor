#include "IccDataExtractor.h"
#include <vector>
using namespace std;

int main(int argc, char* argv[])
{
    IccDataExtractor ex;

    cout << "GetReaders\n";
    cout << "Number of connected readers: " << ex.GetReaders() << endl;


    int reader_nb = 0; // it's hardcoded for now but it should be a parameter with Veracrypt
    cout << "GettingPAN\n";
    try {
        string pan = ex.GettingPAN(reader_nb);
        cout << pan << endl;
    }
    catch (const ICCExtractionException& ex) {
        cout << "Error when getting Data: " << ex.ErrorMessage();
    }

    cout << "GettingAllCerts\n";
    try {
        vector<char> res = ex.GettingAllCerts(reader_nb);
        for (auto val : res) printf("%02X", val);
        cout << "\n";
        cout << "All the data has been extracted ! \n";
        cout << "EMV Part DONE!!!\n";
    }
    catch (const ICCExtractionException& ex) {
        cout << "Error when getting Data: " << ex.ErrorMessage();
    }

}