import json
import time
from crypto.nooCrypto import NooCrypto
from crypto.mrkl import NooTree

class JsonPackets():

    @staticmethod
    def chooserTransaction(cryptor:NooCrypto, blockchain_height): # Транзакция выбора ноды для работы
        temp = json.dumps({'TT': 'CT', 'SENDER': cryptor.getPublicKey(), "NBH": blockchain_height, "TST": str(int(time.time()))}, separators=(',', ':'))
        sign = cryptor.signMessage(temp)
        jtemp = json.loads(temp)
        jtemp.update({'SIGNATURE':sign})
        return json.dumps(jtemp, separators=(',', ':'))

    @staticmethod
    def standartTransacton(cryptor:NooCrypto, reciever:str, token_count:int, token_type:str): # Стандартная транзакция перевода средств
        temp = json.dumps({'TT': 'ST', 'SENDER': cryptor.getPublicKey(), 'RECEIVER': reciever, 'TTOKEN':token_type, 'CTOKEN': str(token_count), "TST": str(int(time.time()))}, separators=(',', ':'))
        sign = cryptor.signMessage(temp)
        jtemp = json.loads(temp)
        jtemp.update({'SIGNATURE':sign})
        return json.dumps(jtemp, separators=(',', ':'))

    @staticmethod
    def standartTransactonWithoutSignature(sender:str, reciever:str, token_count:int, token_type:str, sign:str): # Стандартная транзакция перевода средств с указанием принудительной подписи
        temp = json.dumps({'TT': 'ST', 'SENDER': sender, 'RECEIVER': reciever, 'TTOKEN':token_type, 'CTOKEN':token_count, "TST": str(int(time.time())), "SIGNATURE":sign}, separators=(',', ':'))
        return temp

    @staticmethod
    def applicantTransacton(cryptor:NooCrypto, ip:str): # Транзакция заявка на участие в следующем туре валидации
        temp = json.dumps({'TT': 'AT', 'SENDER': cryptor.getPublicKey(), 'IPADR': ip, "TST": str(int(time.time()))}, separators=(',', ':'))
        sign = cryptor.signMessage(temp)
        jtemp = json.loads(temp)
        jtemp.update({'SIGNATURE':sign})
        return json.dumps(jtemp, separators=(',', ':'))

    @staticmethod
    def createPrecommitBlock(cryptor:NooCrypto, ver:str, transactions:set, bheight):
        jtransactions = []
        for tran in transactions:
            jtransactions.append(json.loads(tran))

        block = json.dumps({'TT': 'BL', 'SENDER': cryptor.getPublicKey(), 'VERSION': ver, 'TCOUNT': len(jtransactions), "BHEIGHT": bheight, 'TRANSACTIONS':jtransactions}, separators=(',', ':'))
        sign = cryptor.signMessage(block)
        jblock = json.loads(block)
        jblock.update({'SIGNATURE':sign})

        return json.dumps(jblock, separators=(',', ':'))

    @staticmethod
    def createCommitBlock(cryptor:NooCrypto, preCommitedBlock:str, signs:list):
        block = json.dumps({'TT': 'CB', 'SENDER': cryptor.getPublicKey(), "BLOCK" :json.loads(preCommitedBlock), "SIGNATURES":signs}, separators=(',', ':'))
        sign = cryptor.signMessage(block)
        jblock = json.loads(block)
        jblock.update({'SIGNATURE':sign})
        return json.dumps(jblock, separators=(',', ':'))

    @staticmethod
    def createCommitBlockForResend(cryptor:NooCrypto, block:str):
        block = json.dumps({'TT': 'CBR', 'SENDER': cryptor.getPublicKey(), "BLOCK" :json.loads(block)}, separators=(',', ':'))
        sign = cryptor.signMessage(block)
        jblock = json.loads(block)
        jblock.update({'SIGNATURE':sign})
        return json.dumps(jblock, separators=(',', ':'))

    @staticmethod
    def createCommitBlockForResendHash(cryptor:NooCrypto, block:str, bheight:int):
        block = json.dumps({'TT': 'CBRH', 'SENDER': cryptor.getPublicKey(), "HASH":NooTree.hash(block), "STEM_SIGNATURE": cryptor.signMessage(block), "BHEIGHT": bheight}, separators=(',', ':'))
        sign = cryptor.signMessage(block)
        jblock = json.loads(block)
        jblock.update({'SIGNATURE':sign})
        return json.dumps(jblock, separators=(',', ':'))

    @staticmethod
    def createSignaturePrecommitedBlock(cryptor:NooCrypto, pblock:str, hash:str):
        temp = json.dumps({'TT': 'SG', 'SENDER': cryptor.getPublicKey(), 'HASH': hash,'SIGNPB': cryptor.signMessage(pblock)}, separators=(',', ':'))
        sign = cryptor.signMessage(temp)
        jtemp = json.loads(temp)
        jtemp.update({'SIGNATURE':sign})
        return json.dumps(jtemp, separators=(',', ':'))

    @staticmethod
    def giveAllSizeBlock(cryptor:NooCrypto, NBH:int):
        temp = json.dumps({'TT': 'ASB', 'SENDER': cryptor.getPublicKey(), "NBH": NBH}, separators=(',', ':'))
        sign = cryptor.signMessage(temp)
        jtemp = json.loads(temp)
        jtemp.update({'SIGNATURE':sign})
        return json.dumps(jtemp, separators=(',', ':'))

    @staticmethod
    def createFirstPurifierBlock(cryptor:NooCrypto, addressList:list, keyList:list, bheight:int):
        temp = json.dumps({'TT': 'PURIFIER', 'SENDER': cryptor.getPublicKey(), 'CLEAN_LIST': addressList, 'CLEAN_KEY_LIST': keyList, "BHEIGHT": bheight}, separators=(',', ':'))
        sign = cryptor.signMessage(temp)
        jtemp = json.loads(temp)
        jtemp.update({'SIGNATURE':sign})
        return json.dumps(jtemp, separators=(',', ':'))

    @staticmethod
    def createPurifierBlock(cryptor:NooCrypto, addressList:list, keyList:list, bheight:int):
        temp = json.dumps({'TT': 'PURIFIER', 'SENDER': cryptor.getPublicKey(), 'CLEAN_LIST': addressList, 'CLEAN_KEY_LIST': keyList, "BHEIGHT": bheight}, separators=(',', ':'))
        sign = cryptor.signMessage(temp)
        jtemp = json.loads(temp)
        jtemp.update({'SIGNATURE':sign})
        return json.dumps(jtemp, separators=(',', ':'))

    @staticmethod
    def createСomplaint(cryptor:NooCrypto, evidence_block:str, evidence_transaction:str):
        temp = json.dumps({'TT': 'COMPLAINT', 'SENDER': cryptor.getPublicKey(), 'EVIDENCE_BLOCK': evidence_block, 'EVIDENCE_TRANSACTION': evidence_transaction}, separators=(',', ':'))
        sign = cryptor.signMessage(temp)
        jtemp = json.loads(temp)
        jtemp.update({'SIGNATURE':sign})
        return json.dumps(jtemp, separators=(',', ':'))

    @staticmethod
    def benchmarkTesting(cryptor:NooCrypto, uuid:str):
        temp = json.dumps({'TT': 'BT', 'SENDER': cryptor.getPublicKey(), 'START': uuid}, separators=(',', ':'))
        sign = cryptor.signMessage(temp)
        jtemp = json.loads(temp)
        jtemp.update({'SIGNATURE':sign})
        return json.dumps(jtemp, separators=(',', ':'))

    @staticmethod
    def wantBeApplicant(cryptor:NooCrypto):
        temp = json.dumps({'TT': 'WBA', 'SENDER': cryptor.getPublicKey()}, separators=(',', ':'))
        sign = cryptor.signMessage(temp)
        jtemp = json.loads(temp)
        jtemp.update({'SIGNATURE':sign})
        return json.dumps(jtemp, separators=(',', ':'))

    @staticmethod
    def myBenchmarkResult(cryptor:NooCrypto, result:str, start:str):
        temp = json.dumps({'TT': 'MBR', 'SENDER': cryptor.getPublicKey(), 'RESULT': result, 'START': start}, separators=(',', ':'))
        sign = cryptor.signMessage(temp)
        jtemp = json.loads(temp)
        jtemp.update({'SIGNATURE':sign})
        return json.dumps(jtemp, separators=(',', ':'))

    @staticmethod
    def badAnswer(cryptor:NooCrypto):
        temp = json.dumps({'TT': 'BAN', 'SENDER': cryptor.getPublicKey()}, separators=(',', ':'))
        sign = cryptor.signMessage(temp)
        jtemp = json.loads(temp)
        jtemp.update({'SIGNATURE':sign})
        return json.dumps(jtemp, separators=(',', ':'))

    @staticmethod
    def universalPacket(cryptor:NooCrypto, type:str, value):
        temp = json.dumps({'TT': type, 'DATA': value, 'SENDER': cryptor.getPublicKey()}, separators=(',', ':'))
        sign = cryptor.signMessage(temp)
        jtemp = json.loads(temp)
        jtemp.update({'SIGNATURE':sign})
        return json.dumps(jtemp, separators=(',', ':'))

    @staticmethod
    def checkJSONValidity(rawjson):
        try:
            json.loads(rawjson)
        except ValueError:
            return False
        return True