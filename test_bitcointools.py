# coding: utf8

import src.bitcointools as b

passphrase = "Thongvan Alexis" #this is absolutly not secure
ori_str_ppk = "d9e5e4673c4a2061b37a4a937d63300f61a558b389893d2fbfd933816b96b4c8"
ori_str_pub = "04f8708265244b7e0492c71cd9e75788626160b0447f0343ee4bb5be3c9826d63c909ba37b386a56ca8e75a849ea4080dc4ca924bf114e424e0985b2960037de56"
ori_str_h160 = "c005d6a30ff9341ef56dd7e623812c2ceca8e020"
ori_str_addr = '1JWKjVZKPtiAyxSjBUk3DtgbcvMrA1BW4f'
print "Original data :"
print "pass phrase to derive key from : '{}'".format(passphrase)
print "original private key : {}".format(ori_str_ppk)
print "original public key : {}".format(ori_str_pub)
print "original h160 key : {}".format(ori_str_h160)
print "original address : {}".format(ori_str_addr)
print ""

print "computation..."
gen_str_ppk = b.compute_private_key(passphrase)
gen_str_pub = b.compute_public_key(gen_str_ppk)
gen_str_h160 = b.compute_hash_160(gen_str_pub)
gen_str_address = b.compute_address_from_hash_160(gen_str_h160)
print "Done."

print ""
print "Verification : "
print "original ppk == generated ppk : {}".format(ori_str_ppk == gen_str_ppk)
print "original pub == generated pub : {}".format(ori_str_pub == gen_str_pub)
print "original h160 == generated h160 : {}".format(ori_str_h160 == gen_str_h160)
print "original addr == generated addr : {}".format(ori_str_addr == gen_str_address)