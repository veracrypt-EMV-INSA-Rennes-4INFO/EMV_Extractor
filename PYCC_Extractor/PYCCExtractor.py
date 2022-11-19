from ast import Is
from re import T
import sys
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnectionObserver import CardConnectionObserver
from smartcard.util import toHexString
from ber_tlv.tlv import *


class TracerAndSELECTInterpreter(CardConnectionObserver):
    """This observer will interprer SELECT and GET RESPONSE bytes
    and replace them with a human readable string."""

    def update(self, cardconnection, ccevent):

        if 'connect' == ccevent.type:
            print('connecting to ' + cardconnection.getReader())

        elif 'disconnect' == ccevent.type:
            print('disconnecting from ' + cardconnection.getReader())

        elif 'command' == ccevent.type:
            str = toHexString(ccevent.args[0])
            str = str.replace("A0 A4 00 00 02", "SELECT")
            str = str.replace("A0 C0 00 00", "GET RESPONSE")
            print('>', str)

        elif 'response' == ccevent.type:
            if [] == ccevent.args[0]:
                print('<  []', "%-2X %-2X" % tuple(ccevent.args[-2:]))
            else:
                print('<',
                      toHexString(ccevent.args[0]),
                      "%-2X %-2X" % tuple(ccevent.args[-2:]))


# define the apdus used in this script
GET_RESPONSE = [0XA0, 0XC0, 00, 00]
SELECT = [00, 0xA4, 0x04, 00, 0x07]
GET_DATA = [0x80, 0xCA]
CPCL_ID = [0x9F, 0x7F]
# Application Identifier (AID) on 7 bytes + 1 byte to complete the apdu
MASTERCARD = [0xA0, 00, 00, 00, 0x04, 0x10, 0x10, 0x00]
VISA = [0xA0, 00, 00, 00, 0x03, 0x10, 0x10, 0x00]
CB = [0xA0, 00, 00, 00, 0x42, 0x10, 0x10, 0x00]
AMEX = [0xA0, 00, 00, 00, 00, 0x25, 0x10, 0x00]  # not sure about this one

APPS = {"MASTERCARD": MASTERCARD, "VISA": VISA, "CB": CB, "AMEX": AMEX}
# not sur for accesses of mastercard et american express
ACCESS = {"MASTERCARD": 0x61, "VISA": 0x6C, "CB": 0x6C, "AMEX": 0x90}
ICC = {}
ISSUER = {}
CPCL = ""
APDUS = {}

# we request any type and wait for 10s for card insertion
cardtype = AnyCardType()
cardrequest = CardRequest(timeout=10, cardType=cardtype)
cardservice = cardrequest.waitforcard()

# create an instance of our observer and attach to the connection
observer = TracerAndSELECTInterpreter()
cardservice.connection.addObserver(observer)


print("Try to connect...")
cardservice.connection.connect()
print("Connected !\n")
card_ok = False


def connect_app(name):
    apdu = SELECT
    if(name in APPS):
        apdu = apdu + APPS[name]
        response, sw1, sw2 = cardservice.connection.transmit(apdu)
        if sw1 == 0x61:
            apdu = [00, 0xC0, 00, 00, 0x49]
            response, sw1, sw2 = cardservice.connection.transmit(apdu)
            if sw1 == ACCESS[name]:
                print(name, "accessed with apdu", apdu, "!")
                APDUS[name] = {}
                APDUS[name]["access"] = apdu
                return True
            else:
                print("Error : wrong access.")
                return False
        else:
            print("Error : no", name, "on this card.")
            return False
    else:
        print("Error :", name, "is not supported by this script.")
        return False


def get_certificates(name):
    icc = False
    issuer = False
    for sfi in range(1, 32):  # parse les dossiers racine
        for rec in range(1, 17):  # parse les fichiers
            apdu = [00, 0xB2, rec, (sfi << 3) | 4, 0x00]
            response = cardservice.connection.transmit(apdu)
            if response[1] == 0x6A:  # no record
                pass
            # record ok but wrong lenth, good length is in the next byte
            elif response[1] == 0x6C:
                apdu[4] = response[2]
                new_resp = cardservice.connection.transmit(apdu)
                # format the response with hex values to be parsed in BER.TLV
                strhex = ''.join('%02x' % value for value in new_resp[0])
                parsed = Tlv.parse(binascii.unhexlify(strhex))
                if len(parsed) >= 1:
                    for tagg in parsed[0][1]:
                        if tagg != 0:
                            # ICC public key certificate tag is 0x9F46
                            if tagg[0] == 0x9F46:
                                APDUS[name]["icc"] = apdu
                                ICC[name] = tagg[1].hex()
                                icc = True
                            # Issuer public key certificate tag is 0x90
                            elif tagg[0] == 0x90:
                                APDUS[name]["issuer"] = apdu
                                ISSUER[name] = tagg[1].hex()
                                issuer = True
                            elif icc and issuer:
                                return
            else:
                print("Unexpected behavior : " + str(response))
    
def get_cpcl_data():
    global CPCL
    apdu = GET_DATA + CPCL_ID + [0x00]
    response = cardservice.connection.transmit(apdu)
    if response[1] == 0x6A:  # no record
        print("Error : no CPCL data on this card.")
        pass
    elif response[1] == 0x6C:
        apdu[4] = response[2]
        APDUS["CPCL"] = {}
        APDUS["CPCL"]["get data"] = apdu
        
        new_resp = cardservice.connection.transmit(apdu)
        strhex = ''.join('%02x' % value for value in new_resp[0])
        CPCL = strhex
    else:
        print("Unexpected behavior : " + str(response))



def get_apps_certificates():
    card_ok = False
    for name in APPS:
        if(connect_app(name)):
            card_ok = True
            get_certificates(name)  
    if(not card_ok):
        print("Error : this card doesn't contain any application supported by this script.")


def print_certificates():
    print("\n---------------\nCertificates in this card :")
    for app, icc in ICC.items():
        print("ICC PK certificate of", app, "is :", icc)
    for app, issuer in ISSUER.items():
        print("Issuer PK certificate of", app, "is :", issuer)
    print("---------------\n")


def print_apdus():
    print("\n---------------\nAPDUS in this card :")
    for app, apdus in APDUS.items():
        print("Application :", app)
        for action, apdu in apdus.items():
            print("Action :", action, ", with apdu :", apdu)
    print("---------------\n")

def print_cpcl():
    print("\n---------------\nCPCL in this card :")
    print(CPCL)
    print("---------------\n")

get_cpcl_data()
get_apps_certificates()
print_cpcl()
print_certificates()
print_apdus()


if 'win32' == sys.platform:
    print('press Enter to continue')
    sys.stdin.read(1)
