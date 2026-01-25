import base64
import os
from lxml import etree
try:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5
except ImportError:
    from Cryptodome.PublicKey import RSA
    from Cryptodome.Cipher import PKCS1_v1_5

def debug():
    # Paths
    activation_xml = "activation.xml"
    
    if not os.path.exists(activation_xml):
        print("Required files missing")
        return

    # Load activation
    with open(activation_xml, "rb") as f:
        activationxml = etree.parse(f)
    
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    pk_node = activationxml.find(".//%s" % adNS("privateLicenseKey"))
    
    key_data = base64.b64decode(pk_node.text)
    # Try with the 26-byte skip
    userkey = key_data[26:]
    
    try:
        rsakey = RSA.importKey(userkey)
        print(f"RSA Key Size: {rsakey.size_in_bytes()} bytes")
    except Exception as e:
        print(f"Failed to import key: {e}")
        return
    
    # Encrypted book key from fulfillment response
    encrypted_bookkey_b64 = "N9XhpY8akSkscrbzSGl/Ut3Vz/yCCcw/NBSVOVkdqYUTMlhmHTC1m8V+bbAjiHcOGjNB+vUsgV13MzaEqQ0NjuPYweYcFJBJe7+9G6jOb1RmuqP7MZAd/o8N9ccWnIks/+AnpMsoRvc57I4sJYR+Yg30dKKmVcchj7LNVj0m2hE="
    encrypted_bookkey = base64.b64decode(encrypted_bookkey_b64)
    
    print(f"Encrypted bookkey length: {len(encrypted_bookkey)} bytes")
    
    # Try standard PKCS#1 v1.5 decryption
    sentinel = b"FAILURE"
    decrypted = PKCS1_v1_5.new(rsakey).decrypt(encrypted_bookkey, sentinel)
    
    if decrypted == sentinel:
        print("Standard PKCS1_v1_5 decryption failed with key[26:].")
        
        # Try without skip
        try:
            rsakey2 = RSA.importKey(key_data)
            decrypted2 = PKCS1_v1_5.new(rsakey2).decrypt(encrypted_bookkey, sentinel)
            if decrypted2 != sentinel:
                print("Decryption successful with full key_data!")
                print(f"Book key (hex): {decrypted2.hex()}")
                return
        except:
            pass
            
        print("Both failed.")
    else:
        print(f"Decryption successful with key[26:]! Book key (hex): {decrypted.hex()}")

if __name__ == "__main__":
    debug()