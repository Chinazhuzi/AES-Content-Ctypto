import random
import time
from Crypto.Util.number import bytes_to_long
from Crypto.Util.number import long_to_bytes
Sbox=[[0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
 [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
 [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
 [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
 [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
 [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
 [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
 [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
 [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
 [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
 [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
 [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
 [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
 [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
 [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
 [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]]
Matrix=[[0x2, 0x3, 0x1, 0x1],
 [0x1, 0x2, 0x3, 0x1],
 [0x1, 0x1, 0x2, 0x3],
 [0x3, 0x1, 0x1, 0x2]]
Rcon=[0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
def xunhuanzuoyi(word,num):
    #将 1 个字中的 4 个字节循环左移num个字节
    return word[num:] + word[:num]
def xunhuanzuoyi2(word, num):
    # 将一个数字的二进制表示左移 num 位
    word_size = 8
    return (word << num) & 0xFF
def xunhuanyouyi(word, num):
    # 将一个数字的二进制表示循环右移 num 位
    word_size = 8
    return ((word >> num) | (word << (word_size - num))) & 0xFF
def generate_round_key(key):
    round_key = [key[0:4], key[4:8], key[8:12], key[12:16]]
    for i in range(4, 44):
        if i % 4 == 0:  # 字循环,字节代换,轮常量
            a1 = xunhuanzuoyi(round_key[i-1], 1)
            a2 = [Sbox[a1[j] >> 4][a1[j] & 0xf] for j in range(4)] # S盒替换
            a2[0] ^= Rcon[i//4 - 1]
            round_key.append([round_key[i-4][j] ^ a2[j] for j in range(4)])
        else:
            round_key.append([round_key[i-4][j] ^ round_key[i-1][j] for j in range(4)])
    return round_key
def ShiftRows(state):
    return [[state[0][0], state[1][1], state[2][2], state[3][3]],
            [state[1][0], state[2][1], state[3][2], state[0][3]],
            [state[2][0], state[3][1], state[0][2], state[1][3]],
            [state[3][0], state[0][1], state[1][2], state[2][3]]]
def ShiftRowsInverse(state):
    return [[state[0][0], state[3][1], state[2][2], state[1][3]],
            [state[1][0], state[0][1], state[3][2], state[2][3]],
            [state[2][0], state[1][1], state[0][2], state[3][3]],
            [state[3][0], state[2][1], state[1][2], state[0][3]]]
def transpose(matrix):#矩阵转置
    rows = len(matrix)
    cols = len(matrix[0])
    transposed_matrix = [[0 for _ in range(rows)] for _ in range(cols)]
    for i in range(rows):
        for j in range(cols):
            transposed_matrix[j][i] = matrix[i][j]
    return transposed_matrix
def MixColumns(state):
    state1 = transpose(state)
    for r in range(4):
        for i in range(4):
            result = [0x1b, 0x1b, 0x1b, 0x1b]
            for j in range(4):
                if Matrix[i][j] == 1:
                    result[j]=state1[j][r]
                if Matrix[i][j] == 2:
                     if state1[j][r] & 0x80:
                        result[j] = ((xunhuanzuoyi2(state1[j][r],1))^0x1b)
                     else:
                         result[j] = (xunhuanzuoyi2(state1[j][r], 1))
                if Matrix[i][j] == 3:
                    tool1=state1[j][r]
                    tool2=state1[j][r]
                    if tool2 & 0x80:
                        tool2=((xunhuanzuoyi2(tool2,1)) ^ 0x1b)
                    else:
                        tool2=(xunhuanzuoyi2(tool2,1))
                    result[j]=tool1^tool2
            state[i][r]=result[0]^result[1]^result[2]^result[3]
    return state
def MixColumnsInverse(state):
    state1 = transpose(state)
    for r in range(4):
        for i in range(4):
            result = [0x1b, 0x1b, 0x1b, 0x1b]
            for j in range(4):
                coef = Matrix2[i][j]
                if coef == 0x0e:
                    if state1[j][r] & 0x80:
                        tool1 = ((xunhuanzuoyi2(state1[j][r], 1)) ^ 0x1b)
                    else:
                        tool1 = (xunhuanzuoyi2(state1[j][r], 1))
                    if tool1 & 0x80:
                        tool2 = ((xunhuanzuoyi2(tool1, 1)) ^ 0x1b)
                    else:
                        tool2 = (xunhuanzuoyi2(tool1, 1))
                    if tool2 & 0x80:
                        tool3 = ((xunhuanzuoyi2(tool2, 1)) ^ 0x1b)
                    else:
                        tool3 = (xunhuanzuoyi2(tool2, 1))
                    result[j] = (tool1 ^ tool2 ^ tool3)
                elif coef == 0x0b:
                    tool1=(state1[j][r])
                    if state1[j][r] & 0x80:
                        tool2 = ((xunhuanzuoyi2(state1[j][r], 1)) ^ 0x1b)
                    else:
                        tool2 = (xunhuanzuoyi2(state1[j][r], 1))
                    if tool2 & 0x80:
                        tool3 = ((xunhuanzuoyi2(tool2, 1)) ^ 0x1b)
                    else:
                        tool3 = (xunhuanzuoyi2(tool2, 1))
                    if tool3 & 0x80:
                        tool3 = ((xunhuanzuoyi2(tool3, 1)) ^ 0x1b)
                    else:
                        tool3 = (xunhuanzuoyi2(tool3, 1))
                    result[j] = (tool1 ^ tool2 ^ tool3)
                elif coef == 0x0d:
                    tool1=(state1[j][r])
                    if tool1 & 0x80:
                        tool2 = ((xunhuanzuoyi2(tool1, 1)) ^ 0x1b)
                    else:
                        tool2 = (xunhuanzuoyi2(tool1, 1))
                    if tool2 & 0x80:
                        tool2 = ((xunhuanzuoyi2(tool2, 1)) ^ 0x1b)
                    else:
                        tool2 = (xunhuanzuoyi2(tool2, 1))
                    if tool2 & 0x80:
                        tool3 = ((xunhuanzuoyi2(tool2, 1)) ^ 0x1b)
                    else:
                        tool3 = (xunhuanzuoyi2(tool2, 1))
                    result[j] = (tool1 ^ tool3^tool2)
                elif coef == 0x09:
                    tool1 = (state1[j][r])
                    if tool1 & 0x80:
                        tool2 = ((xunhuanzuoyi2(tool1, 1)) ^ 0x1b)
                    else:
                        tool2 = (xunhuanzuoyi2(tool1, 1))
                    if tool2 & 0x80:
                        tool2 = ((xunhuanzuoyi2(tool2, 1)) ^ 0x1b)
                    else:
                        tool2 = (xunhuanzuoyi2(tool2, 1))
                    if tool2 & 0x80:
                        tool2 = ((xunhuanzuoyi2(tool2, 1)) ^ 0x1b)
                    else:
                        tool2 = (xunhuanzuoyi2(tool2, 1))
                    result[j] = (tool1 ^ tool2)
            state[i][r] = result[0] ^ result[1] ^ result[2] ^ result[3]
    return state

def Encry(state, key):
    round_key = generate_round_key(key)
    #print('--->',round_key)
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]
    for r in range(1, 10):
        for i in range(4):
            for j in range(4):
                # print(state[i][j] >> 4,state[i][j] & 0xf)
                state[i][j] = Sbox[state[i][j] >> 4][state[i][j] & 0xf]
        state = ShiftRows(state)
        state = MixColumns(state)
        state=transpose(state)
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key[r * 4 + i][j]
    for i in range(4):
        for j in range(4):
            state[i][j] = Sbox[state[i][j] >> 4][state[i][j] & 0xf]
    state = ShiftRows(state)
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[40 + i][j]
    return state
######################################################################################
Sbox2=[[0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
 [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
 [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
 [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
 [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
 [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
 [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
 [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
 [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
 [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
 [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
 [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
 [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
 [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
 [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
 [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]]
Matrix2=[[0x0e, 0x0b, 0x0d, 0x09],
 [0x09, 0x0e, 0x0b, 0x0d],
 [0x0d, 0x09, 0x0e, 0x0b],
 [0x0b, 0x0d, 0x09, 0x0e]]
def Decry(CipherText,Key):
    round_key = generate_round_key(Key)
    for i in range(4):
        for j in range(4):
            CipherText[i][j] ^= round_key[40 + i][j]
    for r in range(9, 0, -1):
        # CipherText=transpose(CipherText)
        CipherText = ShiftRowsInverse(CipherText)
        for i in range(4):
            for j in range(4):
                CipherText[i][j] = Sbox2[CipherText[i][j] >> 4][CipherText[i][j] & 0xf]
        for i in range(4):
            for j in range(4):
                CipherText[i][j] ^= round_key[r * 4 + i][j]
        # for row in CipherText:
        #     for i in row:
        #         print(hex(i),end=' ')
        #     print()
        CipherText = MixColumnsInverse(CipherText)
        CipherText= transpose(CipherText)
    CipherText = ShiftRowsInverse(CipherText)
    for i in range(4):
        for j in range(4):
            CipherText[i][j] = Sbox2[CipherText[i][j] >> 4][CipherText[i][j] & 0xf]
    for i in range(4):
        for j in range(4):
            CipherText[i][j] ^= round_key[i][j]
    return CipherText
##########################################################################################
# Key=[0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf]
# Plaintext=[[0x00,0x11,0x22,0x33],
#               [0x44,0x55,0x66,0x77,],
#               [0x88,0x99,0xaa,0xbb],
#               [0xcc,0xdd,0xee,0xff]]
# CipherText=(Encry(Plaintext, Key))
# print(f"CipherText:{CipherText}")
# result=(Decry(CipherText,Key))
Key=input("请输入Key的值：")
byte_strings = Key.split(',')
Key = [int(byte_str.strip(), 16) for byte_str in byte_strings]
content = input('加密，请输入通讯内容：')
content = bytes(content, encoding='utf-8')
plaintexts=content
if len(str(plaintexts))%16!=0:
    plaintexts=plaintexts+(16-len((plaintexts))%16)*b'\x00'
byte_list=[]
for i in range(0,len(plaintexts),16):
    byte_list.append(plaintexts[i:i+16])
flat_bytes = [byte for sublist in byte_list for byte in sublist]
chunk_size = 16
chunked_bytes = [flat_bytes[i:i + chunk_size] for i in range(0, len(flat_bytes), chunk_size)]
matrix_chunks = [ [chunk[i:i + 4] for i in range(0, 16, 4)] for chunk in chunked_bytes ]
for i in range(len(matrix_chunks)):
    matrix_chunks[i]=Encry(matrix_chunks[i],Key)
decrypt_bytes = [byte for sublist in matrix_chunks for byte in sublist]
flattened = [item for sublist in decrypt_bytes for item in sublist]
byte_data = bytes(flattened)
print('加密后的密文是',bytes_to_long(byte_data))
caonima=input('解密，请输入密文：')
caonima=int(caonima)
caonima=long_to_bytes(caonima)
byte_list=[]
for i in range(0,len(caonima),16):
    byte_list.append(caonima[i:i+16])
flat_bytes = [byte for sublist in byte_list for byte in sublist]
chunked_bytes = [flat_bytes[i:i + chunk_size] for i in range(0, len(flat_bytes), chunk_size)]
matrix_chunks = [ [chunk[i:i + 4] for i in range(0, 16, 4)] for chunk in chunked_bytes ]
for i in range(len(matrix_chunks)):
    matrix_chunks[i]=Decry(matrix_chunks[i],Key)
decrypt_bytes = [byte for sublist in matrix_chunks for byte in sublist]
flattened = [item for sublist in decrypt_bytes for item in sublist]
byte_data = bytes(flattened)
print(byte_data.decode('utf-8'))