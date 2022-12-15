import base64
import ecdsa
import time
    
class Ecc(object):
   def __init__(self):
        
        self.public_key_path = ['pubkey_ECC_2.txt','pubkey_ECC_2.txt','pubkey_ECC_2.txt','pubkey_ECC_2.txt']    ###第一個改一，測試重放攻擊
        self.privaue_key_path = ['privkey_ECC_2.txt','privkey_ECC_2.txt','privkey_ECC_2.txt','privkey_ECC_2.txt']

   def sign_ECDSA_msg(self,msg_hash,port): #簽章
       
       with open(self.privaue_key_path[port % 5000],mode='r') as f:
             private_key = f.read()
             f.close()
       byte_msg_hash = msg_hash.encode()
       sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1)
       signature = base64.b64encode(sk.sign(byte_msg_hash))
       while (len(signature) - 1) == 0: ##test
           signature = base64.b64encode(sk.sign(byte_msg_hash))  ##test
       return signature

   def validate_signature(self,signature, msg_hash,port):
       
        signature = base64.b64decode(signature + b'=' * (4-len(signature) % 4)) ####改，不然會出事
        #signature = base64.b64decode(signature) ####改，不然會出事
        with open(self.public_key_path[port % 5000],mode='r') as f:
                public_key = f.read()
                f.close()
        public_key = (base64.b64decode(public_key)).hex()
        vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
        
        try:
            print("[TSET_TRUE]")
            vk.verify(signature, msg_hash.encode())
            print(vk.verify(signature, msg_hash.encode()))
            return vk.verify(signature, msg_hash.encode())
        except:
            print("[TSET_FALSE]")
            for a in range(len(self.public_key_path)):
                #print(a)
                with open(self.public_key_path[a],mode='r') as f:
                    public_key = f.read()
                    f.close()
                public_key = (base64.b64decode(public_key)).hex()
                vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
                # Try changing into an if/else statement as except is too broad.
                try:
                    vk.verify(signature, msg_hash.encode())
                    #print(vk.verify(signature, msg_hash.encode()))
                    print("[ECC.py_double attack]")
                    return "[double attack]"
                except:
                    #pass
                    #print("None")
                    if a == len(self.public_key_path) - 1:
                        #print("None")
                        return None
        
        for a in range(len(self.public_key_path)):
            #print(a)
            with open(self.public_key_path[a],mode='r') as f:
                public_key = f.read()
                f.close()
            public_key = (base64.b64decode(public_key)).hex()
            vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
            # Try changing into an if/else statement as except is too broad.
            try:
                vk.verify(signature, msg_hash.encode())
                print(vk.verify(signature, msg_hash.encode()))
                return vk.verify(signature, msg_hash.encode())
            except:
                #pass
                #print("None")
                if a == len(self.public_key_path) - 1:
                    #print("None")
                    return None
            
if __name__ == "__main__":
    
    for a in range(30):
        ecc_obj = Ecc() # 例項化 
        #msg_hash = '我是真心喜歡你的。skjbkj'
        block = "id:67" + \
                "timestamp:1669797773.02" + \
                "nonce:4187988449" + \
                "prev_hash:5275a9aee372b7e8f76c9f91ee61b7e2ce5a5f351d032b241e37ce847f68c727" + \
                "information.data:test 20000187 port 5000" + \
               ".pos_trust:[376, 265, 243, 342]" + \
               ".pos:1" + \
               ".pos_mine:172.30.4.65 5002" + \
               "source:172.30.4.65 5000" 
        msg_hash = block
        print("msg_hash:",msg_hash)
        signature = ecc_obj.sign_ECDSA_msg(msg_hash,5000) # 簽章
        print("[test_type]",type(signature))
        print("en_plain:",signature)
        #signature = signature.decode('utf-8')
        print(type(signature))
        print("en_plain_1:",signature)
        #print(signature,msg_hash)
        ecc_obj.validate_signature(signature,msg_hash,5000) # 驗證
        time.sleep(3)