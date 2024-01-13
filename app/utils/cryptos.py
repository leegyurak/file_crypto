import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from app.errors import InvalidDecryptKeyError, InvalidKeySizeError


class AES256FileCrypto():
    def __init__(self, plain_key: str):
        self.key: bytes = bytes(plain_key.encode("utf-8"))
        if len(self.key) != 32:
            raise InvalidKeySizeError("32자리 문자열을 입력해주세요.")
        
    def _create_encrypt_file_name(self, original_file: bytes, extension: str) -> str:
        sha256_hash_obj = hashlib.sha256()

        # 데이터 업데이트
        sha256_hash_obj.update(original_file)

        # 해시 값 추출
        hash_result = sha256_hash_obj.hexdigest()

        return f"{hash_result}.{extension}"

    def encrypt_file(self, unencrypt_file_path: str) -> None:
        cipher = AES.new(self.key, AES.MODE_CBC)
        iv = cipher.iv

        with open(unencrypt_file_path, 'rb') as f:
            plaintext = f.read()

        # 데이터 패딩
        plaintext = pad(plaintext, AES.block_size)

        # 파일에 초기화 벡터 및 암호문 저장
        with open(self._create_encrypt_file_name(plaintext, unencrypt_file_path.split(".")[1]), 'wb') as f:
            f.write(iv)
            f.write(cipher.encrypt(plaintext))

    def decrypt_file(self, encrypt_file_path: str) -> None:
        with open(encrypt_file_path, 'rb') as f:
            iv = f.read(16)  # 16바이트는 AES 블록 크기와 일치
            ciphertext = f.read()

        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        # 복호화 후 언패딩
        try:
            decrypted_data: bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
        except ValueError:
            raise InvalidDecryptKeyError("잘못된 키를 받았습니다.")

        # 복호화된 데이터를 파일에 저장
        with open(f"{encrypt_file_path.split('.')[0]}_decrypted.{encrypt_file_path.split('.')[1]}", 'wb') as f:
            f.write(decrypted_data)
