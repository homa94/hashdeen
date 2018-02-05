#!/usr/bin/env python3

import hashlib
import optparse
import sys

# This is  a main class for encryption and decryption process.
class TheHash:

    def Hash(self, hash_type):
        text = self.encode("utf-8")
        the_hash = hashlib.new(hash_type)
        the_hash.update(text)
        return the_hash.hexdigest()

# This class is a startup class.
class theStart:

    script_name = sys.argv[0]
    print()
    ListOfHashes = {"md5": "md5", "md4": "md4", "md5-sha1": "md5-sha1", "sha1": "sha1", "sha224": "sha224",
                    "sha256": "sha256", "sha384": "sha384", "sha512": "sha512", "blake2b512": "blake2b512",
                    "blake2s256": "blake2s256", "whirlpool": "whirlpool", "ripemd160": "ripemd160"}

    parser = optparse.OptionParser("\n  python3 %s [options]"%(script_name))

    parser.add_option("-a", "--any", dest="word_hash", type="string", help="write anything you like to encrypt.")
    parser.add_option("-t", "--type", dest="type_hash", type="string", help="specify the type of hash.")
    parser.add_option("-w", "--word", dest="word_list", type="string", help="path to wordlist.")
    parser.add_option("-m", "--many", dest="many", type="int", help="encrypted the hash many times.")
    parser.add_option("-e", "--enc", dest="encrypt", type="string", help="the encrypted hash.")

    (options, args) = parser.parse_args()

    if (options.word_hash == None) and (options.type_hash == None):

        print("Try 'hashdeen -h \ --help' for more options.")
        exit(0)

    else:
        run = TheHash
        word_hash = options.word_hash
        type_hash = options.type_hash
        word_list = options.word_list
        encrypt = options.encrypt
        many = options.many

# This function it can encrypt anything you write for one time and with many kind of hashes.
def Encryption():

    start = theStart()

    # Encryption the hash.
    if start.type_hash == start.ListOfHashes.get(start.type_hash):
            print(start.run.Hash(self=start.word_hash, hash_type=start.type_hash))

# This function it can encrypt anything you write for number of times you decide and with many kind of hashes.
def ManyEncryption():

    start = theStart()

    if start.type_hash == start.ListOfHashes.get(start.type_hash):
            start.word_hash = start.run.Hash(self=start.word_hash, hash_type=start.type_hash)
            print(0, start.word_hash)
            for i in range(start.many):
                start.word_hash = start.run.Hash(self=start.word_hash, hash_type=start.type_hash)
                print(i+1, start.word_hash)

# This function it can decrypt anything you write one time and with many kind of hashes.
def Decryption():

    start = theStart()

    # Decryption the hash from word list.

    if start.type_hash == start.ListOfHashes.get(start.type_hash):
        with open(start.word_list, encoding="ISO-8859-1") as WordList:
            for i in WordList.readlines():
                i = i.strip("\n")
                if start.run.Hash(self=i, hash_type=start.type_hash) == start.encrypt:
                    print(i)
                    break

# This function it can decrypt anything you write for number of times you decide and with many kind of hashes
def ManyDecryption():

    start = theStart()

    if start.type_hash == start.ListOfHashes.get(start.type_hash):
        with open(start.word_list, encoding="ISO-8859-1") as WordList:
            for i in WordList.readlines():
                i = i.strip("\n")
                start.word_hash = i
                for l in range(start.many):
                    i = start.run.Hash(self=i, hash_type=start.type_hash)
                    if i == start.encrypt:
                        print(start.word_hash, "encrypted", l, "times")
                        break
                break

# This is a main function decides what function should be run from script.
def main():

    start = theStart()

    if (start.options.word_hash != None) and (start.options.type_hash != None) and (start.options.many == None):
        Encryption()

    elif (start.options.word_hash != None) and (start.options.type_hash != None) and (start.options.many != None):
        ManyEncryption()

    elif (start.options.word_list != None) and (start.options.encrypt != None) and (start.options.type_hash != None) and (start.options.many == None):
        Decryption()

    elif (start.options.word_list != None) and (start.options.encrypt != None) and (start.options.type_hash != None) and (start.options.many != None):
        ManyDecryption()

# Main function start from here.
if __name__ == "__main__":
    main()
