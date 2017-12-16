# coding: utf-8
# yes, that header is valid :)

import base58
import binascii
import ecdsa
import hashlib
import os

secp256k1curve = ecdsa.ellipticcurve.CurveFp(115792089237316195423570985008687907853269984665640564039457584007908834671663, 0, 7)
secp256k1point = ecdsa.ellipticcurve.Point(secp256k1curve, 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
secp256k1 = ecdsa.curves.Curve('secp256k1', secp256k1curve, secp256k1point, (1, 3, 132, 0, 10))

def compute_private_key(very_random_string):
    return hashlib.sha256(very_random_string).hexdigest()

def compute_public_key(str_private_key):
    pko = ecdsa.SigningKey.from_secret_exponent(int(str_private_key, 16), secp256k1)
    return'04' + binascii.b2a_hex(pko.get_verifying_key().to_string())

def compute_hash_160(str_public_key):
    str_sha256_pub = hashlib.sha256(binascii.a2b_hex(str_public_key)).hexdigest()
    return hashlib.new('ripemd160', binascii.a2b_hex(str_sha256_pub)).hexdigest()

def compute_address_from_hash_160(str_hash_160):
    main_network = '00'
    marked_hash_160 = main_network + str_hash_160
    pre_checksum = hashlib.sha256(binascii.a2b_hex(marked_hash_160)).hexdigest()
    checksum = hashlib.sha256(binascii.a2b_hex(pre_checksum)).hexdigest()
    address = marked_hash_160 + checksum[:8]
    b58_address = base58.b58encode(binascii.a2b_hex(address))
    return b58_address
    
def compute_address_from_public_key(str_public_key):
    str_hash_160 = compute_hash_160(str_public_key)
    return compute_address_from_hash_160(str_hash_160)

def compute_address_from_private_key(str_private_key):
    str_public_key = compute_public_key(str_private_key)
    return compute_address_from_public_key(str_public_key)
