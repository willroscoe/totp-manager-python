#!/usr/bin/env python

"""
A TOTP (2FA) Manager with encrypted file storage
Version: 1.1

Data file compatible with .Net core console version at: https://github.com/bifter/totp-manager-dotnetcore

TOTP: Adapted from https://github.com/gingerlime/hotpie

Encryption: AES (MODE_CBC) with HMAC authentication based on C# https://gist.github.com/jbtule/4336842

This work (A TOTP Manager with encrypted file storage), is free of known copyright restrictions.
http://creativecommons.org/publicdomain/mark/1.0/ 

BASIC USAGE:
Display list of saved totp codes: ./totp.py {passsword} 
Add new totp secret: ./totp.py {password} -a {title} {base32 totp secret}
"""

import sys, os, copy, argparse, json, math

#for encryption (AES)
import base64, hashlib
try:
    import Crypto
except ImportError:
    print('Error: PyCrypto is not installed.')
    sys.exit(1)

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA256
import StringIO
import binascii

# For 2FA functions
import hmac, struct, time

PATH_TO_SHARED_DATAFILE = os.path.expanduser('~/Will/Code/shareddata/') # path to data file
ENCRYPTEDKEYS_FILENAME = 'totp_encrypted.txt' # filename of data file
DEFAULT_TOTP_DIGITS = 6
MIN_PASSWORD_LENGTH = 6 # Should be 15!

def main():
    global ENCRYPTEDKEYS_FILENAME
    os.system('cls' if os.name=='nt' else 'clear') # clear the screen

    print('') # add line break on the screen

    parser = argparse.ArgumentParser(epilog='Keyfile path: ' + PATH_TO_SHARED_DATAFILE + ENCRYPTEDKEYS_FILENAME)
    parser.add_argument('password', help='Common password to decrypt data')
    parser.add_argument('-v', '--verbose', nargs='?', default=False, const=True, help='Include any additional en/decryption information')
    parser.add_argument('-id', '--ident', nargs=1, type=int, default=0, help='ID of item')
    parser.add_argument('-title', '--title', nargs=1, default=None, help='title of item')
    parser.add_argument('-secret', '--secret', nargs=1, default=None, help='base32 secret of item')
    parser.add_argument('-digits', '--digits', nargs=1, type=int, default=0, help='digits on item')
    parser.add_argument('-tab', '--tab', nargs='?', default=False, const=True, help='use tab spacing in output')
    parser.add_argument('-f', '--file', nargs=1, default=None, help='Use this data filename')

    group = parser.add_mutually_exclusive_group() # only allow 1 of the following arguments to be used at once
    group.add_argument('-d', '--displayorig', nargs='?', default=False, const=True, help='Display original data')
    group.add_argument('-a', '--add', nargs='+', help='Add new totp item: {title} {base32 totp secret} {digits (optional)}')
    group.add_argument('-u', '--update', nargs='?', default=False, const=True, help='Update an item by ID: -id {ID} -title {title} -secret {base32 totp secret} -digits {digits')
    group.add_argument('-del', '--delete', nargs=1, type=int, help='Delete an item by ID: -id {ID}')
    group.add_argument('-pu', '--passwordupdate', nargs=1, help='Update encryption password: {new password}')
    #group.add_argument('-c', '--convert', nargs='?', default=False, const=True, help='Convert data to new format')
    args = parser.parse_args()

    if len(args.password) < MIN_PASSWORD_LENGTH:
        print('Error: The minimum password length is {0:d}\n'.format(MIN_PASSWORD_LENGTH))
        sys.exit()

    if args.file:
        if len(args.file) > 0:
            ENCRYPTEDKEYS_FILENAME = args.file[0]

    if args.displayorig:
        DisplayUnencryptedData(args.password)
    elif args.add:
        _digits = DEFAULT_TOTP_DIGITS
        _secret = ''
        _title = args.add[0]
        if len(args.add) < 2:
            print('The new item is missing required values. Please try again.')
            sys.exit()
        else:
            if len(args.add) > 1:
                _secret = args.add[1]
            if len(args.add) > 2:
                _digits = args.add[2]
        AddNewItem(args.password, _title, _secret, _digits)

        DisplayTOTPList(args.password, args.tab) # once added display the list again

    elif args.update:
        if args.ident == False:
            print('Missing ID.')
            sys.exit()

        _id = args.ident[0]
        _title = None
        _digits = -1
        _secret = None
        if args.title:
            if len(args.title) > 0:
                _title = args.title[0]
        if args.secret:
            if len(args.secret) > 0:
                _secret = args.secret[0]
        if args.digits:
            if len(args.digits) > 0:
                _digits = args.digits[0]

        UpdateItem(args.password, _id, _title, _secret, _digits)
        DisplayTOTPList(args.password, args.tab) # once done display the list again

    elif args.delete:
        DeleteItemFromList(args.password, args.delete[0])
        DisplayTOTPList(args.password, args.tab) # once done display the list again

    elif args.passwordupdate:
        UpdatePassword(args.password, args.passwordupdate[0])
    # elif args.convert:
    #    ConvertDataFormat(args.password)
    else:
        DisplayTOTPList(args.password, args.tab)

    print('') # add line break on the screen

 
def DisplayTOTPList(_password, _usetabs = False):
    json_object = LoadAndDecryptToJsonObject(_password)
    if len(json_object) == 0:
        print('No items to display! Add an item.')
    else:
        # first loop through the list to calc the column spacing
        _maxtitlelength = 0
        for item in json_object:
            if len(item['name']) > _maxtitlelength:
                _maxtitlelength = len(item['name'])
        _titlecolumnspacing = _maxtitlelength + 4 # the max number of character spacing required for the title (with a bit more)
        
        _item_count = 1
        if _usetabs:
            _format = '{0:2}{1}\t{2}{3}{4}'
            print(_format.format('ID', ':', 'TITLE', '\t'*CalcTabSpacing(_titlecolumnspacing, len('TITLE')), 'TOKEN\n'))
        else:
            _format = '{0:2}{1:3}{2:' + str(_titlecolumnspacing) + '}{3}'
            print(_format.format('ID', ':', 'TITLE', 'TOKEN\n'))

        for item in json_object:
            _digits = item['digits']
            _secret = item['secret']
            _finaldigits = _digits if _digits > 0 else DEFAULT_TOTP_DIGITS
            _finalsecret = base64.b32decode(AddPaddingForBase32(_secret), True) # ensure correct padding for Base32 decrypted key
            _totp_token = TOTP(_finalsecret, digits=_finaldigits)

            if _usetabs:
                print(_format.format(_item_count, ':', item['name'], '\t'*CalcTabSpacing(_titlecolumnspacing, len(item['name'])), _totp_token))
            else:
                print(_format.format(_item_count, ':', item['name'], _totp_token))
            _item_count += 1

    print('') # add line break on the screen


def CalcTabSpacing(_titlecolumnspacing, _textlength):
    _chars2Tab = 8
    _maxcharsfortabs = (math.ceil(_titlecolumnspacing / _chars2Tab) * _chars2Tab) + 8
    charsToMax = _maxcharsfortabs - _textlength
    return int(math.ceil(charsToMax / _chars2Tab))


def DisplayUnencryptedData(_password, _format = 'json'):
    if _format == 'json':
        json_object = LoadAndDecryptToJsonObject(_password, False, True)
        print(json.dumps(json_object, sort_keys=True, indent=4))
    else: # default to json
        print('Defaulting to json format:\n\n')
        json_object = LoadAndDecryptToJsonObject(_password)
        print(json.dumps(json_object, sort_keys=True, indent=4))


def AddNewItem(_password, _title, _secret, _digits = DEFAULT_TOTP_DIGITS):
    _isvalid = True
    # check inputs are valid
    _secretWithPadding = AddPaddingForBase32(_secret) # ensure correct padding for Base32 decrypted key
    try:
        secret = base64.b32decode(_secretWithPadding, True)
    except:
        _isvalid = False
        print('The totp secret was the wrong length!')
        pass

    if _isvalid:
        json_object = LoadAndDecryptToJsonObject(_password)
        if _digits < 1:
            _digits = DEFAULT_TOTP_DIGITS

        new_item = {}
        new_item['name'] = _title
        new_item['digits'] = _digits
        new_item['secret'] = _secret
        json_object.append(new_item)
        json_object = sorted(json_object, key=getSortKey) # sort data on 'name' key
        
        EncryptJsonAndSave(_password, json_object)
        print('...Item added ok.')

    else:
        print('Error: One or more totp inputs were not valid. Data not saved.')
        sys.exit()

    
def UpdateItem(_password, _id, _title, _secret, _digits):
    json_object = LoadAndDecryptToJsonObject(_password)
    if len(json_object) == 0:
        print('No items to display! Add an item.')
        sys.exit()
    else:
        if _id <= len(json_object) and _id > 0:
        
            if _title is not None:
                json_object[_id - 1]['name'] = _title
            if _secret is not None:
                json_object[_id - 1]['secret'] = _secret
            if _digits > -1:
                json_object[_id - 1]['digits'] = _digits

            json_object = sorted(json_object, key=getSortKey) # sort data on 'name' key
            EncryptJsonAndSave(_password, json_object)
            print('Item updated ok.')

        else:
            print('Error: ID not found.')
            sys.exit()
    
def DeleteItemFromList(_password, _idtodelete):
    json_object = LoadAndDecryptToJsonObject(_password)
    if len(json_object) == 0:
        print('No items to display! Add an item.')
        sys.exit()
    else:
        if _idtodelete <= len(json_object) and _idtodelete > 0:
            del json_object[_idtodelete - 1]
            EncryptJsonAndSave(_password, json_object)
        else:
            print('Error: ID not found.')
            sys.exit()


def UpdatePassword(_password, _new_password):
    _okToSave = True
    json_object = LoadAndDecryptToJsonObject(_password)
    # validate new password
    if _password == _new_password:
        print('The new password is the same as the old one.')
        _okToSave = False
    if len(_new_password) < MIN_PASSWORD_LENGTH:
        print('Error: the password must be at least {0:d} characters long. Password has not been updated.'.format(MIN_PASSWORD_LENGTH)) 
        _okToSave = False
    if len(_new_password) < 10:
        print('Info: the password should ideally be longer than 10 characters.')
    if _okToSave:
        EncryptJsonAndSave(_new_password, json_object) # save with new password
        print('Password updated.')
        _password = _new_password


def AddPaddingForBase32(_string):
    return _string + '=' * ((8 - len(_string) % 8) % 8) # ensure correct padding for Base32 decrypted key


## Commented out as it's not for everyday usage
# def ConvertDataFormat(_password):
#     json_object = LoadAndDecryptToJsonObject(_password)
#     json_data = []
#     for key in sorted(json_object):
#         thedigits = 0
#         thesecret = ''
#         value = json_object[key]
#         if ITEM_FIELD_SECRET in value:
#             thesecret = value[ITEM_FIELD_SECRET]
#         if ITEM_FIELD_DIGITS in value:
#             thedigits = value[ITEM_FIELD_DIGITS]
#         _finaldigits = thedigits if thedigits > 0 else DEFAULT_TOTP_DIGITS
#         new_item = {}
#         new_item['name'] = key
#         new_item['digits'] = _finaldigits
#         new_item['secret'] = thesecret
#         json_data.append(new_item)
    
#     json_data = sorted(json_data, key=getSortKey) # sort data on 'name' key 
#     output_data = {}
#     output_data['data'] = json_data
#     _data = json.dumps(output_data)
#     encryped_data = EncryptWithPassword(_data, _password, None, False)
#     global PATH_TO_SHARED_DATAFILE

#     if os.path.isdir(PATH_TO_SHARED_DATAFILE) == False:
#         print('Warning: Data file directory: {0} not found. Reverting to ./'.format(PATH_TO_SHARED_DATAFILE))
#         PATH_TO_SHARED_DATAFILE = './'

#     file = open(PATH_TO_SHARED_DATAFILE + 'newformatdata.txt', 'w')
#     file.write(encryped_data) # save all keys
#     file.close


#---------------------------------
# LOADING DATA FUNCTIONS - BEGIN 
#- - - - - - - - - - - - - - - - -

def LoadDataFromFile(_verbose = False):
    global PATH_TO_SHARED_DATAFILE
    if os.path.isdir(PATH_TO_SHARED_DATAFILE) == False:
        print('Warning: Data file directory: {0} not found. Reverting to ./'.format(PATH_TO_SHARED_DATAFILE))
        PATH_TO_SHARED_DATAFILE = './'

    if os.path.isfile(PATH_TO_SHARED_DATAFILE + ENCRYPTEDKEYS_FILENAME):
        file = open(PATH_TO_SHARED_DATAFILE + ENCRYPTEDKEYS_FILENAME, 'r') 
        result = file.read()
        file.close()

        if len(result) > 0: # check if the file has data
            return result
        else:
            if _verbose:
                print('Data file is empty.')
    else:
        if _verbose:
            print('Data file does not exist in directory: {0}.'.format(PATH_TO_SHARED_DATAFILE))

    return None


def LoadAndDecryptToJsonObject(_password, _verbose = False, _raw = False):
    encrypteddata = LoadDataFromFile(_verbose)
    if encrypteddata is None:
        json_object = {}
    else:
        plainJsonString = DecryptWithPassword(encrypteddata, _password, 0, False)
        if plainJsonString is not None:
            json_object = json.loads(plainJsonString)
            if not _raw:
                json_object = sorted(json_object['data'], key=getSortKey)
        else:
            print('Password might be incorrect.\n')
            sys.exit()

    return json_object

def getSortKey(item): # used to sort the data on the 'name' key
    return item['name']

# - - - - - - - - - - - - - - - 
# - LOADING DATA FUNCTIONS - END
# -------------------------------


# ------------------------------
# - SAVE DATA FUNCTIONS - BEGIN 
# - - - - - - - - - - - - - - -

def EncryptJsonAndSave(_password, _data):
    output_data = {}
    output_data['data'] = _data
    _data = json.dumps(output_data)

    encryped_data = EncryptWithPassword(_data, _password, None, False)
    SaveStringToFile(encryped_data)


def SaveStringToFile(_data):
    global PATH_TO_SHARED_DATAFILE

    if os.path.isdir(PATH_TO_SHARED_DATAFILE) == False:
        print('Warning: Data file directory: {0} not found. Reverting to ./'.format(PATH_TO_SHARED_DATAFILE))
        PATH_TO_SHARED_DATAFILE = './'

    file = open(PATH_TO_SHARED_DATAFILE + ENCRYPTEDKEYS_FILENAME, 'w')
    file.write(_data) # save all keys
    file.close
    #print('...Data saved ok.')


# - - - - - - - - - - - - - -
# - SAVE DATA FUNCTIONS - END 
# ----------------------------


 
# ------------------------
# - 2FA functions - BEGIN
# - - - - - - - - - - - -

def HOTP(K, C, digits=DEFAULT_TOTP_DIGITS, digestmod=hashlib.sha1):
    C_bytes = struct.pack(b"!Q", C)
    hmac_digest = hmac.new(key=K, msg=C_bytes,
                           digestmod=digestmod).hexdigest()
    return Truncate(hmac_digest)[-digits:]


def TOTP(K, digits=DEFAULT_TOTP_DIGITS, incRemaining=True, window=30, clock=None, digestmod=hashlib.sha1):
    
    if clock is None:
        clock = time.time()
    C = int(clock / window)

    _hotp = HOTP(K, C, digits=digits, digestmod=digestmod)

    if (incRemaining):
        #Calc Time remaining for this C
        time_of_next_C = (C + 1) * window
        diff_of_now_and_next_C = int(time_of_next_C - clock) # seconds
        return '{0:12}Remaining Secs: {1}'.format(_hotp, diff_of_now_and_next_C)

    return _hotp

def Truncate(hmac_digest):
    offset = int(hmac_digest[-1], 16)
    binary = int(hmac_digest[(offset * 2):((offset * 2) + 8)], 16) & 0x7fffffff
    return str(binary)

# - - - - - - - - - - -
# - 2FA functions - END
# ----------------------


# -------------------------------
# - Encryption functions - BEGIN
# - - - - - - - - - - - - - - - 

# AES (MODE_CBC) with HMAC authentication

#BlockBitSize = 128
KeyBitSize = 256
SaltBitSize = 64
Iterations = 10000
PKCS7_k = 16 # padding multiple

def EncryptWithPassword(message, password, nonSecretPayload = None, show_variables = False):

    secretMessage = message.encode('utf-8')

    if nonSecretPayload is None:
         nonSecretPayload = bytes()

    payload = bytes()

    if (len(nonSecretPayload) > 0):
        payload = bytes(nonSecretPayload)

    #Use Random Salt to prevent pre-generated weak password attacks.
    cryptSalt = Random.new().read(SaltBitSize/8)
    cryptKey = hashlib.pbkdf2_hmac('sha1', password, cryptSalt, Iterations, KeyBitSize / 8)

    #Create Non Secret Payload
    payload += cryptSalt[:]
    payloadIndex = len(payload)

    #Deriving separate key, might be less efficient than using HKDF, 
    #but now compatible with RNEncryptor which had a very similar wireformat and requires less code than HKDF.
    authSalt = Random.new().read(SaltBitSize / 8)
    authKey = hashlib.pbkdf2_hmac('sha1', password, authSalt, Iterations, KeyBitSize / 8)

    #Create Rest of Non Secret Payload
    payload += authSalt[0:]

    #User Error Checks
    if cryptKey == None or len(cryptKey) != KeyBitSize / 8:
        print("cryptKey needs to be %d bit!" % KeyBitSize)
    if authKey == None or len(authKey) != KeyBitSize / 8:
        print("authKey needs to be %d bit!" % KeyBitSize)

    if secretMessage == None or len(secretMessage) < 1:
        print("Secret Data Required!")

    #non-secret payload optional
    if payload is None:
        payload = bytes()

    iv = Random.new().read(AES.block_size)
    cipher = AES.new(cryptKey, AES.MODE_CBC, iv)
    cipherText = cipher.encrypt(PKCS7Encode(secretMessage)) # Note: calling cipher.encrypt more than once changes the result
    # assemble encrypted message and add authentication
    data = payload + iv + cipherText 
    sig = hmac.new(authKey, data, hashlib.sha256).digest()
    # end
    EncodeMsg = base64.b64encode(data + sig)

    if show_variables:
        print('cryptSalt: {0:s}'.format(base64.b32encode(cryptSalt)))
        print('authSalt: {0:s}'.format(base64.b32encode(authSalt)))
        print('payload: {0:s}'.format(base64.b32encode(payload)))
        print('iv: {0:s}'.format(base64.b32encode(iv)))
        print('cipherText: {0:s}'.format(base64.b32encode(cipherText)))
        print('data: {0:s}'.format(base64.b32encode(data)))
        print('sig: {0:s}'.format(base64.b32encode(sig)))
        print('')
        print('EncodeMsg: {0:s}'.format(EncodeMsg))

    return EncodeMsg


def DecryptWithPassword(message, password, nonSecretPayloadLength = 0, show_variables = False):

    if (message is None):
        print('Encrypted Data Required!')

    encryptedMessage = bytes(base64.b64decode(message))

    # User Error Checks
    if password is None or len(password) < MIN_PASSWORD_LENGTH:
        print('Must have a password of at least {0:d} characters!'.format(MIN_PASSWORD_LENGTH))

    if encryptedMessage is None or len(encryptedMessage) == 0:
        print('Encrypted Data Required!')

    # Grab Salt from Non-Secret Payload
    cryptSalt = encryptedMessage[nonSecretPayloadLength:nonSecretPayloadLength + (SaltBitSize / 8)]
    authSalt = encryptedMessage[nonSecretPayloadLength + len(cryptSalt):nonSecretPayloadLength + len(cryptSalt) + (SaltBitSize / 8)]

    if show_variables:
        print('cryptSalt: {0:s}'.format(base64.b32encode(cryptSalt)))
        print('authSalt: {0:s}'.format(base64.b32encode(authSalt)))


    # Generate crypt key
    cryptKey = hashlib.pbkdf2_hmac('sha1', password, cryptSalt, Iterations, KeyBitSize / 8) 

    # Generate auth key
    authKey = hashlib.pbkdf2_hmac('sha1', password, authSalt, Iterations, KeyBitSize / 8)

    if show_variables:
        print('cryptKey: {0:s}'.format(base64.b32encode(cryptKey)))
        print('authKey: {0:s}'.format(base64.b32encode(authKey)))

    nonSecretPayloadLengthIncSalts = nonSecretPayloadLength + len(cryptSalt) + len(authSalt)
    # Basic Usage Error Checks
    if cryptKey is None or len(cryptKey) != KeyBitSize / 8:
        print('CryptKey needs to be {0:d} bit!'.format(KeyBitSize))

    if authKey is None or len(authKey) != KeyBitSize / 8:
        print('AuthKey needs to be {0:d} bit!'.format(KeyBitSize))

    if encryptedMessage is None or len(encryptedMessage) == 0:
        print('Encrypted Data Required!')

    sentTag = bytes()

    # Calculate Tag
    calcTag = hmac.new(authKey, encryptedMessage[0:len(encryptedMessage) - (KeyBitSize / 8)], hashlib.sha256).digest()

    if show_variables:
        print('calcTag: {0:s}'.format(base64.b32encode(calcTag)))

    ivLength = AES.block_size

    # if message length is to small just return null
    if len(encryptedMessage) < (KeyBitSize / 8) + nonSecretPayloadLengthIncSalts + ivLength:
        print('Data length is incorrect!')
        return None

    # Grab Sent Tag
    sentTag = encryptedMessage[len(encryptedMessage) - (KeyBitSize / 8):]

    if show_variables:
        print('sentTag: {0:s}'.format(base64.b32encode(sentTag)))

    # Compare SentTag and Calc Tag
    if sentTag != calcTag:
        print('Data failed authentication!')
        return None

    # Grab iv from message
    iv = encryptedMessage[nonSecretPayloadLengthIncSalts:nonSecretPayloadLengthIncSalts + ivLength]

    if show_variables:
        print('iv: {0:s}'.format(base64.b32encode(iv)))

    message_section = encryptedMessage[nonSecretPayloadLengthIncSalts + ivLength:len(encryptedMessage) - (KeyBitSize / 8)]

    cipher = AES.new(cryptKey, AES.MODE_CBC, iv)
    msg = cipher.decrypt(message_section)

    return PKCS7Decode(msg).decode("utf-8")


def PKCS7Encode(text):
    l = len(text)
    output = StringIO.StringIO()
    val = PKCS7_k - (l % PKCS7_k)
    for _ in xrange(val):
        output.write('%02x' % val)
    return text + binascii.unhexlify(output.getvalue())

def PKCS7Decode(text):
    nl = len(text)
    val = int(binascii.hexlify(text[-1]), 16)
    if val > PKCS7_k:
        raise ValueError('Input is not padded or padding is corrupt')

    l = nl - val
    return text[:l]

# - - - - - - - - - - - - - - 
# - Encryption functions - END
# -----------------------------


if __name__ == '__main__':
    main()