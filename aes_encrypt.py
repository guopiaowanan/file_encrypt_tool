
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

def aes_encrypt(key, data):
    """
    功能：aes加密函数，将文本内容加密
    参数：key，秘钥（16位）  data，待加密文本
    返回值：已加密文本
    
    """
    cipher = AES.new(key, AES.MODE_CBC, key)  # 设置AES加密模式 此处设置为CBC模式
    block_size = AES.block_size
    
    # data = data.encode()
    # 判断data是不是16的倍数，如果不是用b'\0'补足
    if len(data) % block_size != 0:
        add = block_size - (len(data) % block_size)
        data += b'\0' * add
    
    encrypted = cipher.encrypt(data)  # aes加密
    result = binascii.b2a_hex(encrypted)  # b2a_hex encode  将二进制转换成16进制
    return result

def folder_encrypt(dir_name):
    """
    功能：将某个文件夹中的所有文件加密
    参数：dir_name，绝对路径
    返回值：无
    """
    key = b"qazwsxedcrfvtgby" 
    for root, dir, file in os.walk(dir_name):
        for f in file:
            file_path = os.path.join(root,f)
            temp_path = file_path + "temp"
    
            with open(file_path,"rb") as f:
                data = f.read()
                
            # 文件内容加密
            encrypt_tmp = aes_encrypt(key,data)
            with open(temp_path,"ab") as t:
                t.write(encrypt_tmp)
            
            f_md5 = get_md5(file_path)
            os.remove(file_path) # 加密文件覆盖源文件
            os.rename(temp_path, file_path)
            
            



if __name__ == "__main__":
    data = b"1234567823"
    key = b"qazwsxedcrfvtgby"  

    # 字符串加密
    encrypt_text = aes_encrypt(key,data)  
    print(encrypt_text)

    

    # # 遍历某个文件夹，加密该文件
    folder_encrypt(r"C:\Users\Administrator\Desktop\呵呵")
