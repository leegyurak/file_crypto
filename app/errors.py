class InvalidDecryptKeyError(Exception):
    """
    잘못된 복호화키를 입력함.
    """
    pass


class InvalidKeySizeError(Exception):
    """
    입력한 키 사이즈와 필요한 키 사이즈가 다름.
    """
    pass
