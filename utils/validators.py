def validate_binary(text: str, length: int) -> bool:
    """
    验证二进制字符串
    """
    if len(text) != length:
        return False
    return all(bit in '01' for bit in text)


def validate_hex(text: str, length: int) -> bool:
    """
    验证十六进制字符串
    """
    if len(text) != length:
        return False
    try:
        int(text, 16)
        return True
    except ValueError:
        return False