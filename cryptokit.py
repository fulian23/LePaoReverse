from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad, pad
import base64,json,hmac,hashlib


def data_decrypt(encrypted_base64_text, KEY, IV):
    """
    使用 AES-CBC 模式和 PKCS7 填充解密 Base64 编码的文本。

    参数:
    encrypted_base64_text (str): Base64 编码的密文。

    返回:
    str: 解密后的明文字符串，如果解密失败则返回 None。
    """
    try:
        encrypted_bytes = base64.b64decode(encrypted_base64_text)

        cipher = AES.new(KEY, AES.MODE_CBC, IV)

        decrypted_padded_bytes = cipher.decrypt(encrypted_bytes)

        decrypted_unpadded_bytes = unpad(decrypted_padded_bytes, AES.block_size, style='pkcs7')

        decrypted_text = decrypted_unpadded_bytes.decode('utf-8')

        return decrypted_text
    except ValueError as e:
        print(f"解密过程中发生错误 (ValueError): {e}")
        print("请检查密钥、IV、密文是否正确，以及填充方式是否为 PKCS7。")
        return None
    except Exception as e:
        print(f"解密过程中发生未知错误: {e}")
        return None
def data_encrypt(plain_text, key_bytes, iv_bytes):
    """
    使用 AES-CBC 模式和 PKCS7 填充加密文本，然后进行 Base64 编码。

    参数:
    plain_text (str): 要加密的明文字符串。
    key_bytes (bytes): AES 密钥 (例如 16, 24, 或 32 字节)。
    iv_bytes (bytes): 初始化向量 (必须是 16 字节，与 AES.block_size 相同)。

    返回:
    str: Base64 编码的密文字符串，如果加密失败则返回 None。
    """
    try:
        plain_bytes = plain_text.encode('utf-8')

        padded_bytes = pad(plain_bytes, AES.block_size, style='pkcs7')

        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)

        encrypted_bytes = cipher.encrypt(padded_bytes)

        encrypted_base64_text = base64.b64encode(encrypted_bytes).decode('utf-8')

        return encrypted_base64_text
    except Exception as e:
        print(f"加密过程中发生错误: {e}")
        return None
def data_sign(data_dict, salt):
    """
    实现与 JavaScript 中 SignMD5 类似的签名逻辑。

    参数:
    data_dict (dict): 包含参数的字典。
    salt (str): 用于增加安全性的盐值或密钥。

    返回:
    str: 计算得到的 MD5 签名字符串 (小写十六进制)。
    """
    if not isinstance(data_dict, dict):
        raise TypeError("Input data must be a dictionary.")
    if not isinstance(salt, str):
        raise TypeError("Salt must be a string.")

    sorted_keys = sorted(data_dict.keys())

    string_to_sign = ""
    for key in sorted_keys:
        value = data_dict[key]
        string_to_sign += str(key) + str(value)

    string_to_sign += salt

    md5_hash = hashlib.md5(string_to_sign.encode('utf-8')).hexdigest()

    return md5_hash
def oss_post_sgin(access_key_secret: str, policy_document: dict) -> tuple[str, str]:
    """
    为 OSS POST Object 请求生成 policy 和 signature。

    参数:
    access_key_secret (str): 用于签名的 AccessKeySecret。
    policy_document (dict): 上传策略文档 (Python 字典形式)。

    返回:
    tuple[str, str]: 一个包含 (base64_encoded_policy, signature) 的元组。
    """

    policy_json_str = json.dumps(policy_document, separators=(',', ':'))

    base64_encoded_policy = base64.b64encode(policy_json_str.encode('utf-8')).decode('utf-8')

    message = base64_encoded_policy.encode('utf-8')
    key = access_key_secret.encode('utf-8')
    h = hmac.new(key, message, hashlib.sha1)
    binary_signature = h.digest()

    signature = base64.b64encode(binary_signature).decode('utf-8')

    return base64_encoded_policy, signature

if __name__ == "__main__":
    KEY_STR = "Wet2C8d34f62ndi3"
    IV_STR = "K6iv85jBD8jgf32D"
    KEY = KEY_STR.encode('utf-8')
    IV = IV_STR.encode('utf-8')

