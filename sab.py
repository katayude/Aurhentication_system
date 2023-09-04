import logging
import signal
import os
import time
from typing import Any
import pykka
from pykka import debug
import Crypto.Cipher.AES as AES
import secrets

class HomeServer(pykka.ThreadingActor):
    def __init__(self):
        super(HomeServer, self).__init__()

    def link_class(self, instance_name):
        self.PUC_ref = instance_name

    def on_receive(self, message):
        self.message = message
        self.order = message["order"]
        if(self.order == "Send_License_Plate"):
            self.license_plate = message["license_plate"]
            print(2)
            self.Generate_Key()

    def Generate_Key(self):
        self.key = 0x00112233445566778899aabbccddeeff
        print(3)
        self.PUC_ref.tell({"order":"Send_Registration_Complete_Message", "key":self.key})

class PUC(pykka.ThreadingActor):
    def __init__(self):
        super(PUC, self).__init__()

    def link_class(self, instance_name1, instance_name2):
        self.HomeServer_ref = instance_name1
        self.SmartMeter_ref = instance_name2

    def on_receive(self, message):
        self.message = message
        self.order = self.message["order"]
        if(self.order == "Get_License_Plate"):
            self.license_plate = self.message["license_plate"]
            self.Send_License_Plate()
        elif(self.order == "Send_Registration_Complete_Message"):
            self.key = message["key"]
            print(3)
            self.Dtermine_RAND_AMF_OP_SQN()
        elif(self.order == "Forward_Encrypted_RES"):
            self.RES = message["RES"]
            self.Compare_RES_and_XRES()
        
    def Send_License_Plate(self):
        print(2)
        self.HomeServer_ref.tell({"order":"Send_License_Plate", "license_plate":self.license_plate})

    def Dtermine_RAND_AMF_OP_SQN(self):
        self.RAND = secrets.randbelow(2**128)
        self.AMF = 0x1122
        self.OP = 0x00112233445566778899aabbccddeeff
        self.SQN = 0x5566778899aa
        print(4)
        self.Generate_XRES_XMAC()
    
    def Generate_XRES_XMAC(self):
        print(5)
        self.XRES = Create_RES(self.key, self.RAND, self.OP)
        self.XMAC = Create_MAC(self.key, self.RAND, self.AMF, self.OP, self.SQN)
        print(self.XRES)
        print(self.XMAC)
        self.Send_RAND_AMF_SQN_XMAC_1()
    
    def Send_RAND_AMF_SQN_XMAC_1(self):
        self.SmartMeter_ref.tell({"order":"Send_RAND_AMF_SQN_XMAC_1", "RAND":self.RAND, "AMF":self.AMF, "OP":self.OP, "SQN": self.SQN, "XMAC":self.XMAC})

    def Compare_RES_and_XRES(self):
        if(self.XRES == self.RES):
            self.Generate_PUC_MSK()
        else:
            print("error")
        
    def Generate_PUC_MSK(self):
        self.PUC_MSK = "PUC_MSK"
        print(self.PUC_MSK)
    
        


class SmartMeter(pykka.ThreadingActor):
    def __init__(self):
        super(SmartMeter, self).__init__()
    
    def link_class(self, instance_name1, instance_name2):
        self.PUC_ref = instance_name1
        self.ElectricVehicle_ref = instance_name2

    def on_receive(self, message):
        self.message = message
        self.order = message["order"]
        if(self.order == "start"):
            self.license_plate = message["license_plate"]
            print(1)
            self.Get_License_Plate()
        elif self.order == "Send_RAND_AMF_SQN_XMAC_1" :
            self.RAND = self.message["RAND"]
            self.AMF = self.message["AMF"]
            self.OP = self.message["OP"]
            self.SQN = self.message["SQN"]
            self.XMAC = self.message["XMAC"]
            self.Send_RAND_AMF_SQN_XMAC_2()
        elif self.order == "Send_Encrypted_RES":
            self.RES = message["RES"]
            self.Forward_Encrypted_RES()

    def Get_License_Plate(self):
        self.PUC_ref.tell({"order":"Get_License_Plate", "license_plate":self.license_plate})
        print(1)

    def Send_RAND_AMF_SQN_XMAC_2(self):
        self.ElectricVehicle_ref.tell({"order":"Send_RAND_AMF_SQN_XMAC_2", "RAND":self.RAND, "AMF":self.AMF, "OP":self.OP, "SQN": self.SQN, "XMAC":self.XMAC})

    def Forward_Encrypted_RES(self):
        self.PUC_ref.tell({"order":"Forward_Encrypted_RES", "RES":self.RES})


class ElectricVehicle(pykka.ThreadingActor):
    def __init__(self):
        super(ElectricVehicle, self).__init__()

    def link_class(self, instance_name):
        self.SmartMeter_ref = instance_name

    def on_receive(self, message):
        self.message = message
        self.order = message["order"]
        if self.order == "Send_RAND_AMF_SQN_XMAC_2":
            self.RAND = self.message["RAND"]
            self.AMF = self.message["AMF"]
            self.OP = self.message["OP"]
            self.SQN = self.message["SQN"]
            self.XMAC = self.message["XMAC"]
            self.Generate_key()
            self.Generate_RES_AK_CK_IK_MAC()

    def Generate_key(self):
        self.key = 0x00112233445566778899aabbccddeeff

    def Generate_RES_AK_CK_IK_MAC(self):
        self.RES = Create_RES(self.key, self.RAND, self.OP)
        self.MAC = Create_MAC(self.key, self.RAND, self.AMF, self.OP, self.SQN)
        self.AK = Create_AK(self.key, self.RAND, self.OP)
        self.CK = Create_CK(self.key, self.RAND, self.OP)
        self.IK = Create_IK(self.key, self.RAND, self.OP)

        print(self.RES)
        print(self.MAC)
        print(self.AK)
        print(self.CK)
        print(self.IK)

        if(self.MAC == self.XMAC):
            print("Complete!")
            self.Send_Encrypted_RES()
        else:
            print("error")

    def Send_Encrypted_RES(self):
        self.SmartMeter_ref.tell({"order":"Send_Encrypted_RES", "RES":self.RES})



def AES_ECB_encrypt(key, data) :    #key:int16byte, data:int16byte
    key_byte = key.to_bytes(16, 'big')
    data_byte = data.to_bytes(16, 'big')
    decipher = AES.new(key_byte, AES.MODE_ECB)
    enc = decipher.encrypt(data_byte)
    enc = int.from_bytes(enc, 'big')
    return enc                      #enc: int16byte

def Create_OPc(key, OP):  #key:int16byte OP:int16byte
    Ek_OP = AES_ECB_encrypt(key, OP)
    OPc = Ek_OP ^ OP
    return OPc            #OPc:int16byte

def Create_IN1(SQN, AMF):
    IN1 = 0
    IN1 |= SQN << (128 - 48)
    IN1 |= AMF << (128 - 48 - 16)
    IN1 |= SQN << (128 - 48 - 16 - 48)
    IN1 |= AMF
    return IN1

def rotate_left(state, r):
    # 128ビットのマスク
    mask = (1 << 128) - 1

    # rビット左にシフトすると上位からオーバーフローするビット
    overflow = (state >> (128 - r)) & mask

    # xをrビット左にシフトし、オーバーフロー分を右端に加える
    return ((state << r) & mask) | overflow

def get_MAC_A(OUT1):
    """
    This function extracts MAC-A from OUT1.
    """
    # MAC-A[0] .. MAC-A[63] = OUT1[0] .. OUT1[63]
    # Here we are assuming that OUT1 is a 128-bit integer.
    MAC_A = OUT1 >> 64
    return MAC_A

def get_MAC_S(OUT1):
    """
    This function extracts MAC-S from OUT1.
    """
    # MAC-S[0] .. MAC-S[63] = OUT1[64] .. OUT1[127]
    # Here we are assuming that OUT1 is a 128-bit integer.
    MAC_S = OUT1 & ((1 << 64) - 1)
    return MAC_S

def get_RES(OUT2):
    """
    This function extracts RES from OUT2.
    """
    # RES[0] .. RES[63] = OUT2[64] .. OUT2[127]
    RES = OUT2 & ((1 << 64) - 1)
    return RES

def get_CK(OUT3):
    """
    This function extracts CK from OUT3.
    """
    # CK[0] .. CK[127] = OUT3[0] .. OUT3[127]
    CK = OUT3
    return CK

def get_IK(OUT4):
    """
    This function extracts IK from OUT4.
    """
    # IK[0] .. IK[127] = OUT4[0] .. OUT4[127]
    IK = OUT4
    return IK

def get_AK_from_OUT5(OUT5):
    """
    This function extracts AK from OUT5.
    """
    # AK[0] .. AK[47] = OUT5[0] .. OUT5[47]
    AK = OUT5 >> (128 - 48)
    return AK


def Create_MAC(key, RAND, AMF, OP, SQN):
    r1 = 64
    c1 = 0x00000000000000000000000000000000
    OPc = Create_OPc(key, OP)
    state = RAND ^ OPc
    TEMP = AES_ECB_encrypt(key, state)
    IN1 = Create_IN1(SQN, AMF)
    state = IN1 ^ OPc
    state = rotate_left(state, r1)
    state = state ^ c1
    state = state ^ TEMP
    state = AES_ECB_encrypt(key, state)
    OUT1 = state ^ OPc
    MAC_A = get_MAC_A(OUT1)
    MAC_S = get_MAC_S(OUT1)
    return MAC_A

def Create_RES(key, RAND, OP):
    r2 = 0
    c2 = 0x00000000000000000000000000000001
    OPc = Create_OPc(key, OP)
    state = RAND ^ OPc
    TEMP = AES_ECB_encrypt(key, state)
    state = TEMP ^ OPc
    state = rotate_left(state, r2)
    state = state ^ c2
    state = AES_ECB_encrypt(key, state)
    OUT2 = state ^ OPc
    RES = get_RES(OUT2)
    #print(hex(RES))
    return hex(RES)

def Create_CK(key, RAND, OP):
    r3 = 32
    c3 = 0x00000000000000000000000000000002
    OPc = Create_OPc(key, OP)
    state = RAND ^ OPc
    TEMP = AES_ECB_encrypt(key, state)  
    state = TEMP ^ OPc
    state = rotate_left(state, r3)
    state = state ^ c3
    state = AES_ECB_encrypt(key, state)
    OUT3 = state ^ OPc
    #print(hex(OUT3))
    CK = get_CK(OUT3)
    #print(hex(CK))
    return CK

def Create_IK(key, RAND, OP):
    r4 = 64
    c4 = 0x00000000000000000000000000000004
    OPc = Create_OPc(key, OP)
    state = RAND ^ OPc
    TEMP = AES_ECB_encrypt(key, state)
    state = TEMP ^ OPc
    state = rotate_left(state, r4)
    state = state ^ c4
    state = AES_ECB_encrypt(key, state)
    OUT4 = state ^ OPc
    #print(hex(OUT4))
    IK = get_IK(OUT4)
    return IK

def Create_AK(key, RAND, OP):
    r5 = 96
    c5 = 0x00000000000000000000000000000008
    OPc = Create_OPc(key, OP)
    state = RAND ^ OPc
    TEMP = AES_ECB_encrypt(key, state)
    state = TEMP ^ OPc
    state = rotate_left(state, r5)
    state = state ^ c5
    state = AES_ECB_encrypt(key, state)
    OUT5 = state ^ OPc
    #print(hex(OUT5))
    AK = get_AK_from_OUT5(OUT5)
    return AK



def main():
    # デバッグレベルのログが出力されるようにする
    logging.basicConfig(level=logging.DEBUG)

    # シグナル SIGUSR1 でスレッドのトレースバックを出力する
    signal.signal(signal.SIGUSR1, debug.log_thread_tracebacks)

    #アクターの起動
    HomeServer_ref = HomeServer.start()
    PUC_ref = PUC.start()
    SmartMeter_ref = SmartMeter.start()
    ElectricVehicle_ref = ElectricVehicle.start()

    #プロキシの取得
    HomeServer_proxy = HomeServer_ref.proxy()
    PUC_proxy = PUC_ref.proxy()
    SmartMeter_proxy = SmartMeter_ref.proxy()
    ElectricVehicle_proxy = ElectricVehicle_ref.proxy()

    #メッセージを送り合うclassはclass内変数に他の
    HomeServer_proxy.link_class(PUC_ref)
    PUC_proxy.link_class(HomeServer_ref, SmartMeter_ref)
    SmartMeter_proxy.link_class(PUC_ref, ElectricVehicle_ref)
    ElectricVehicle_proxy.link_class(SmartMeter_ref)

    SmartMeter_ref.tell({"order":"start", "license_plate":721})


    time.sleep(10)
    #If you don't let it SLEEP, the actor will stop in the middle and it will not behave properly.

    HomeServer_ref.stop()
    PUC_ref.stop()
    SmartMeter_ref.stop()
    ElectricVehicle_ref.stop()






if __name__ == '__main__':
    main()