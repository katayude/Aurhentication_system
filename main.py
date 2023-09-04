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
        print("")
        print("HS")
        self.message = message
        self.order = message["order"]

        if(self.order == "Send_License_Plate"):
            print("(Home_AKA)Generate_Key")
            self.license_plate = message["license_plate"]
            self.Generate_Key()

    def Generate_Key(self):
        self.key = 0x00112233445566778899aabbccddeeff - self.license_plate
        self.PUC_ref.tell({"order":"Send_Registration_Complete_Message",
                            "key":self.key})

class PUC(pykka.ThreadingActor):
    def __init__(self):
        super(PUC, self).__init__()

    def link_class(self, instance_name1, instance_name2):
        self.HomeServer_ref = instance_name1
        self.SmartMeter_ref = instance_name2

    def on_receive(self, message):
        print("")
        print("PUC")
        self.message = message
        self.order = self.message["order"]
        

        if(self.order == "Get_License_Plate"):
            print("(Home_AKA)Send_License_Plate")
            self.license_plate = self.message["license_plate"]
            self.Send_License_Plate()

        elif(self.order == "Send_Registration_Complete_Message"):
            print("(Home_AKA)Determine_RAND_AMF_SN_SQN")
            self.key = message["key"]
            self.Dtermine_RAND_AMF_OP_SQN()

        elif(self.order == "Forward_Encrypted_RES"):
            self.SQN += 1
            print(f'SQN: {self.SQN}')
            print("(Home_AKA)Compare_RES_and_XRES")
            self.RES = message["RES"]
            self.Compare_RES_and_XRES()

        elif(self.order == "Forward_local_Encrypted_RES"):
            self.SQN += 1
            print(f'SQN: {self.SQN}')
            print("(PUC_AKA)Compare_RES_and_XRES")
            self.local_RES = message["local_RES"]
            self.Compare_local_RES_and_local_XRES()

        elif(self.order == "Get_Local_License_Plate"):
            self.SQN += 1
            print(f'SQN: {self.SQN}')
            print("(PUC_AKA)Compare_License_Plate")
            self.local_license_plate = self.message["license_plate"]
            self.Compare_License_Plate()
        
    def Send_License_Plate(self):
        self.HomeServer_ref.tell({"order":"Send_License_Plate", "license_plate":self.license_plate})

    def Dtermine_RAND_AMF_OP_SQN(self):
        self.RAND = secrets.randbelow(2**128)
        self.AMF = 0x1122
        self.OP = 0x00112233445566778899aabbccddeeff
        self.SQN = secrets.randbelow(2**48)
        ##0x5566778899aa
        self.SQN += 1
        print(f'SQN: {self.SQN}')
        self.Generate_XRES_XMAC()

    
    def Generate_XRES_XMAC(self):
        print("(Home_AKA)Generate_XRES_XMAC")
        self.XRES = Create_RES(self.key, self.RAND, self.OP)
        self.XMAC = Create_MAC(self.key, self.RAND, self.AMF, self.OP, self.SQN)
        print(f'XRES: {self.XRES}')
        print(f'XMAC: {self.XMAC}')
        self.Send_RAND_AMF_SQN_XMAC_1()

    def Generate_Local_XRES_XMAC(self):
        print("(PUC_AKA)Generate_XRES_XMAC")
        self.local_XRES = Create_RES(self.PUC_MSK, self.RAND, self.OP)
        self.local_XMAC = Create_MAC(self.PUC_MSK, self.RAND, self.AMF, self.OP, self.SQN)
        print(f'XRES: {self.local_XRES}')
        print(f'XMAC: {self.local_XMAC}')
        self.Send_local_RAND_AMF_SQN_XMAC_1()

    
    def Send_RAND_AMF_SQN_XMAC_1(self):
        self.SmartMeter_ref.tell({"order":"Send_RAND_AMF_SQN_XMAC_1", "RAND":self.RAND, "AMF":self.AMF, "OP":self.OP, "SQN": self.SQN, "XMAC":self.XMAC})

    def Send_local_RAND_AMF_SQN_XMAC_1(self):
        self.SmartMeter_ref.tell({"order":"Send_local_RAND_AMF_SQN_XMAC_1", "RAND":self.RAND, "AMF":self.AMF, "OP":self.OP, "SQN": self.SQN, "local_XMAC":self.local_XMAC})

    def Compare_RES_and_XRES(self):
        if(self.XRES == self.RES):
            print(f'OK! XRES = RES')
            self.Generate_PUC_MSK()
        else:
            print("error")

    def Compare_local_RES_and_local_XRES(self):
        if(self.local_XRES == self.local_RES):
            print(f'OK! XRES = RES')
        else:
            print("error")
        
    def Generate_PUC_MSK(self):
        self.PUC_MSK = 0x00aabbccddeeff778899aabbccddeeff - self.license_plate
        print(f'PUC_MSK: {self.PUC_MSK}')

    def Compare_License_Plate(self):
        if self.license_plate == self.local_license_plate:
            print("This license plate has been registered")
            self.Generate_Local_XRES_XMAC()

        else:
            print("This license plate has not been registered")
    
        


class SmartMeter(pykka.ThreadingActor):
    def __init__(self):
        super(SmartMeter, self).__init__()
    
    def link_class(self, instance_name1, instance_name2):
        self.PUC_ref = instance_name1
        self.ElectricVehicle_ref = instance_name2

    def on_receive(self, message):
        print("")
        print("SM")
        self.message = message
        self.order = message["order"]

        if(self.order == "start"):
            print("home AKA communication initiation")
            self.license_plate = message["license_plate"]
            self.Get_License_Plate()

        elif self.order == "Send_RAND_AMF_SQN_XMAC_1" :
            print('(Home_AKA)Send_RAND_AMF_SQN_XMAC')
            self.RAND = self.message["RAND"]
            self.AMF = self.message["AMF"]
            self.OP = self.message["OP"]
            self.SQN = self.message["SQN"]
            self.XMAC = self.message["XMAC"]
            self.Send_RAND_AMF_SQN_XMAC_2()

        elif self.order == "Send_Encrypted_RES":
            print("(Home_AKA)Forward_Encrypted_RES")
            self.RES = message["RES"]
            self.Forward_Encrypted_RES()
        
        elif self.order == "local_start":
            print("PUC AKA comunication initation")
            self.local_license_plate = message["license_plate"]
            self.Get_Local_License_Plate()

        elif self.order == "Send_local_RAND_AMF_SQN_XMAC_1":
            print('(PUC_AKA)Send_RAND_AMF_SQN_XMAC')
            self.RAND = self.message["RAND"]
            self.AMF = self.message["AMF"]
            self.OP = self.message["OP"]
            self.SQN = self.message["SQN"]
            self.local_XMAC = self.message["local_XMAC"]
            self.Send_local_RAND_AMF_SQN_XMAC_2()

        elif self.order == "Send_local_Encrypted_RES":
            print("(PUC_AKA)Forward_Encrypted_RES")
            self.local_RES = message["local_RES"]
            self.Forward_local_Encrypted_RES()

            

    def Get_License_Plate(self):
        self.PUC_ref.tell({"order":"Get_License_Plate", "license_plate":self.license_plate})

    def Send_RAND_AMF_SQN_XMAC_2(self):
        self.ElectricVehicle_ref.tell({"order":"Send_RAND_AMF_SQN_XMAC_2", "RAND":self.RAND, "AMF":self.AMF, "OP":self.OP, "SQN": self.SQN, "XMAC":self.XMAC})

    def Send_local_RAND_AMF_SQN_XMAC_2(self):
        self.ElectricVehicle_ref.tell({"order":"Send_local_RAND_AMF_SQN_XMAC_2", "RAND":self.RAND, "AMF":self.AMF, "OP":self.OP, "SQN": self.SQN, "local_XMAC":self.local_XMAC})


    def Forward_Encrypted_RES(self):
        self.PUC_ref.tell({"order":"Forward_Encrypted_RES", "RES":self.RES})

    def Forward_local_Encrypted_RES(self):
        self.PUC_ref.tell({"order":"Forward_local_Encrypted_RES", "local_RES":self.local_RES})
    
    def Get_Local_License_Plate(self):
        self.PUC_ref.tell({"order":"Get_Local_License_Plate", "license_plate":self.local_license_plate})



class ElectricVehicle(pykka.ThreadingActor):
    def __init__(self, license_plate):
        super(ElectricVehicle, self).__init__()
        self.license_plate = license_plate

    def link_class(self, instance_name):
        self.SmartMeter_ref = instance_name

    def on_receive(self, message):
        print("")
        print("EV")
        self.message = message
        self.order = message["order"]

        if self.order == "Send_RAND_AMF_SQN_XMAC_2":
            print("(Home_AKA)Generate_RES_AK_CK_IK_MAC")
            self.RAND = self.message["RAND"]
            self.AMF = self.message["AMF"]
            self.OP = self.message["OP"]
            self.SQN = self.message["SQN"]
            self.XMAC = self.message["XMAC"]
            self.Generate_key()
            self.Generate_RES_AK_CK_IK_MAC()

        elif self.order == "Send_local_RAND_AMF_SQN_XMAC_2":
            print("(PUC_AKA)Generate_RES_AK_CK_IK_MAC")
            self.RAND = self.message["RAND"]
            self.AMF = self.message["AMF"]
            self.OP = self.message["OP"]
            self.SQN = self.message["SQN"]
            self.local_XMAC = self.message["local_XMAC"]
            self.Generate_local_RES_AK_CK_IK_MAC()


    def Generate_key(self):
        self.key = 0x00112233445566778899aabbccddeeff - self.license_plate

    def Generate_RES_AK_CK_IK_MAC(self):
        self.RES = Create_RES(self.key, self.RAND, self.OP)
        self.MAC = Create_MAC(self.key, self.RAND, self.AMF, self.OP, self.SQN)
        self.AK = Create_AK(self.key, self.RAND, self.OP)
        self.CK = Create_CK(self.key, self.RAND, self.OP)
        self.IK = Create_IK(self.key, self.RAND, self.OP)

        print(f'RES: {self.RES}')
        print(f'MAC: {self.MAC}')
        print(f'AK: {self.AK}')
        print(f'CK: {self.CK}')
        print(f'IK: {self.IK}')
        #print("PUC_MSK: PUC_MSK")

        if(self.MAC == self.XMAC):
            print("OK! MAC = XMAC")
            self.PUC_MSK = 0x00aabbccddeeff778899aabbccddeeff - self.license_plate
            print(f'PUC_MSK = {self.PUC_MSK}')
            self.Send_Encrypted_RES()
        else:
            print("MAC != XMAC")
    
    def Generate_local_RES_AK_CK_IK_MAC(self):
        self.local_RES = Create_RES(self.PUC_MSK, self.RAND, self.OP)
        self.local_MAC = Create_MAC(self.PUC_MSK, self.RAND, self.AMF, self.OP, self.SQN)
        self.local_AK = Create_AK(self.PUC_MSK, self.RAND, self.OP)
        self.local_CK = Create_CK(self.PUC_MSK, self.RAND, self.OP)
        self.local_IK = Create_IK(self.PUC_MSK, self.RAND, self.OP)

        print(f'RES: {self.local_RES}')
        print(f'MAC: {self.local_MAC}')
        print(f'AK: {self.local_AK}')
        print(f'CK: {self.local_CK}')
        print(f'IK: {self.local_IK}')
        #print("PUC_MSK: PUC_MSK")

        if(self.MAC == self.XMAC):
            print("OK! MAC = XMAC")
            self.Send_local_Encrypted_RES()
        else:
            print("error")

    def Send_Encrypted_RES(self):
        self.SmartMeter_ref.tell({"order":"Send_Encrypted_RES", "RES":self.RES})

    def Send_local_Encrypted_RES(self):
        self.SmartMeter_ref.tell({"order":"Send_local_Encrypted_RES", "local_RES":self.local_RES})

#####################################################################################
#                            key generation algorithm                               #
#####################################################################################

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
    return RES

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
    #Ensure debug-level log output
    logging.basicConfig(level=logging.DEBUG)

    # シグナル SIGUSR1 でスレッドのトレースバックを出力する
    #Output thread traceback with signal SIGUSR1
    signal.signal(signal.SIGUSR1, debug.log_thread_tracebacks)

    #アクターの起動
    #Actor Activation
    HomeServer_ref = HomeServer.start()
    PUC_ref = PUC.start()
    SmartMeter_ref = SmartMeter.start()
    ElectricVehicle_ref = ElectricVehicle.start(721)

    

    #Proxy Acquisition
    HomeServer_proxy = HomeServer_ref.proxy()
    PUC_proxy = PUC_ref.proxy()
    SmartMeter_proxy = SmartMeter_ref.proxy()
    ElectricVehicle_proxy = ElectricVehicle_ref.proxy()

    #通信するアクアーの登録
    #Registration of communicating actors
    HomeServer_proxy.link_class(PUC_ref)
    PUC_proxy.link_class(HomeServer_ref, SmartMeter_ref)
    SmartMeter_proxy.link_class(PUC_ref, ElectricVehicle_ref)
    ElectricVehicle_proxy.link_class(SmartMeter_ref)

    #start communication
    SmartMeter_ref.tell({"order":"start", "license_plate":720})
    
    time.sleep(1)

    SmartMeter_ref.tell({"order":"start", "license_plate":721})


    time.sleep(5)
    SmartMeter_ref.tell({"order":"local_start", "license_plate":721})


    time.sleep(5)
    

    #If you don't let it SLEEP, the actor will stop in the middle and it will not behave properly.



    HomeServer_ref.stop()
    PUC_ref.stop()
    SmartMeter_ref.stop()
    ElectricVehicle_ref.stop()






if __name__ == '__main__':
    main()