import binascii

"""Chave/semente estática para geração de keystream"""
ACP_STATIC_KEY = binascii.unhexlify("5b6faf5d9d5b0e1351f2da1de7e8d673")

def generate_acp_keystream(length):
	"""Obtém a chave usada para criptografar a chave do cabeçalho (e alguns dados da mensagem?)
	
	Args:
		length (int): comprimento do keystream a ser gerado
	
	Returns:
		Bytes do comprimento solicitado
	
	Note:
		O keystream se repete a cada 256 bytes
	
	"""
	key = bytearray(length)
	for key_idx in range(length):
		key[key_idx] = (key_idx + 0x55 & 0xFF) ^ ACP_STATIC_KEY[key_idx % len(ACP_STATIC_KEY)]
	return bytes(key)
