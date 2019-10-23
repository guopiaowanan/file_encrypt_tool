
from Crypto.Cipher import AES
import binascii
import os
import hashlib

def get_md5(f_abs_path):
    """
    功能：获取单个接收文件的MD5值
    参数：f_abs_path，文件绝对路径
    返回值：f_md5，文件的MD5值
    """
    with open(f_abs_path,"rb") as f:
        data = f.read()
    m = hashlib.md5()
    m.update(data)
    f_md5 = m.hexdigest()
    print(f_abs_path,"写入成功，MD5值为：",f_md5)
    return f_md5

def aes_decrypt(key, data, last=False):
    """
    功能：aes解密
    参数: key，秘钥  data，需解密文本
    返回值:解密后的文本
    """
    cipher = AES.new(key, AES.MODE_CBC, key)
    
    result2 = binascii.a2b_hex(data)  # 十六进制还原成二进制
    decrypted = cipher.decrypt(result2)
    decrypted = decrypted.rstrip(b'\0')
    return decrypted  

def file_decrypto(file_path):
    temp_path = file_path  + "已解密"
    key = b"qazwsxedcrfvtgby"

    with open(file_path,"rb") as f:
        data = f.read()
    decrypt_tmp = aes_decrypt(key,data)
    with open(temp_path,"ab") as t:
        t.write(decrypt_tmp)

    f_md5 = get_md5(temp_path)
    
    os.remove(file_path)
    os.rename(temp_path, file_path)

if __name__ == "__main__":
    data = b"1234567823"
    key = b"qazwsxedcrfvtgby"  
    
    # 字符串解密
    decrypt_text = aes_decrypt(key,encrypt_text)
    print(decrypt_text)

    
    # 给某个加密的文件解密
    file_decrypto(r"C:\Users\Administrator\Desktop\呵呵\新建文本文档.txt")