import binascii
import logging
import os
import struct
import time

from .cflbinary import CFLBinaryPListComposer, CFLBinaryPListParser
from .message import ACPMessage
from .property import ACPProperty
from .session import ACPClientSession


class ACPClient(object):
	def __init__(self, target, password=""):
		self.target = target
		self.password = password
		
		self.session = ACPClientSession(target, password)
	
	
	def connect(self):
		self.session.connect()
	
	
	def close(self):
		self.session.close()
	
	
	def send(self, data):
		self.session.send(data)
	
	
	def recv(self, size):
		return self.session.recv(size)
	
	
	def recv_message_header(self):
		return self.recv(ACPMessage.header_size)
	
	
	def recv_property_element_header(self):
		return self.recv(ACPProperty.element_header_size)
	
	
	def get_properties(self, prop_names=[]):
		# solicita a propriedade enviando o nome e um valor "nulo"
		payload = b""
		for name in prop_names:
			payload += ACPProperty.compose_raw_element(0, ACPProperty(name))
		
		request = ACPMessage.compose_getprop_command(4, self.password, payload)
		self.send(request)
		
		raw_reply = self.recv_message_header()
		reply_header = ACPMessage.parse_raw(raw_reply)
		
		if reply_header.error_code != 0:
			print("código de erro em get_properties: {0:#x}".format(reply_header.error_code))
			#XXX: blah, o que fazer...
			return []
		
		props = []
		while True:
			prop_header = self.recv_property_element_header()
			name, flags, size = ACPProperty.parse_raw_element_header(prop_header)
			logging.debug("name  ".format(name))
			logging.debug("flags ".format(flags))
			logging.debug("size  ".format(size))
			
			prop_data = self.recv(size)
			logging.debug("prop_data {0!r}".format(prop_data))
			
			if flags & 1:
				(error_code, ) = struct.unpack(">I", prop_data)
				print("erro ao solicitar o valor para a propriedade \"{0}\": {1:#x}".format(name, error_code))
				continue
			
			prop = ACPProperty(name, prop_data)
			logging.debug("prop {0!r}".format(prop))
			
			#XXX: isso ainda está meio feio
			if prop.name is None and prop.value is None:
				logging.debug("encontrado marcador de final de propriedade vazio")
				break
			
			#XXX: deveríamos retornar dict(name=name, prop=ACPProperty(name, value)) em vez disso?
			props.append(prop)
			
		return props
	
	
	def set_properties(self, props_dict={}):
		payload = b""
		for name, prop in props_dict.items():
			logging.debug("prop: {0!r}".format(prop))
			payload += ACPProperty.compose_raw_element(0, prop)
		request = ACPMessage.compose_setprop_command(0, self.password, payload)
		self.send(request)
		
		raw_reply = self.recv_message_header()
		reply_header = ACPMessage.parse_raw(raw_reply)
		
		if reply_header.error_code != 0:
			print("código de erro em set_properties: {0:#x}".format(reply_header.error_code))
			#XXX: blah, o que fazer...
			return
		
		prop_header = self.recv_property_element_header()
		name, flags, size = ACPProperty.parse_raw_element_header(prop_header)
		logging.debug("name  {0!r}".format(name))
		logging.debug("flags {0!r}".format(flags))
		logging.debug("size  {0!r}".format(size))
		
		prop_data = self.recv(size)
		logging.debug("prop_data {0!r}".format(prop_data))
		
		if flags & 1:
			(error_code, ) = struct.unpack(">I", prop_data)
			print("erro ao definir o valor para a propriedade \"{0}\": {1:#x}".format(name, error_code))
			return
			
		prop = ACPProperty(name, prop_data)
		logging.debug("prop {0!r}".format(prop))
		
		#XXX: isso ainda está meio feio
		if prop.name is None and prop.value is None:
			logging.debug("encontrado marcador de final de propriedade vazio")
	
	
	def get_features(self):
		self.send(ACPMessage.compose_feat_command(0))
		
		reply_header = ACPMessage.parse_raw(self.recv_message_header())
		
		reply = self.recv(reply_header.body_size)
		
		return CFLBinaryPListParser.parse(reply)
	
	
	def flash_primary(self, payload):
		self.send(ACPMessage.compose_flash_primary_command(0, self.password, payload))
		
		reply_header = ACPMessage.parse_raw(self.recv_message_header())
		
		return self.recv(reply_header.body_size)
	
	
	def authenticate_AppleSRP(self):
		#XXX: AINDA TESTANDO ESSA MERDA
		import ctypes
		from .clibs import AppleSRP
		from collections import OrderedDict		
		
		username = "admin"
		
		dic = OrderedDict([(u"state", 1), (u"username", username)])
		payload = CFLBinaryPListComposer.compose(dic)
		raw_message = ACPMessage.compose_auth_command(4, payload)
		self.send(raw_message)
		
		raw_reply_header = self.recv_message_header()
		reply_header = ACPMessage.parse_raw(raw_reply_header)
		
		if reply_header.error_code != 0:
			logging.error("código de erro na autenticação: {0:#x}".format(reply_header.error_code))
			#XXX: blah, o que fazer...
			return
		
		logging.debug("recv_size: {0}".format(reply_header.body_size))
		raw_message = self.recv(reply_header.body_size)
		logging.debug("raw_message: {0!r}".format(raw_message))
		params1 = CFLBinaryPListParser.parse(raw_message)
		logging.debug(params1)
		
		n = params1[u"modulus"]
		g = params1[u"generator"]
		salt = params1[u"salt"]
		server_pkey = params1[u"publicKey"]
		
		nhex = binascii.hexlify(n).decode('ascii')
		ghex = binascii.hexlify(g).decode('ascii')
		
		logging.debug("nhex: {0}".format(nhex))
		logging.debug("ghex: {0}".format(ghex))
		logging.debug("salt: {0}".format(binascii.hexlify(salt).decode('ascii')))
		logging.debug("server_pkey: {0}".format(binascii.hexlify(server_pkey).decode('ascii')))
		
		# cria o contexto SRP
		asrp = AppleSRP.SRP_new(AppleSRP.SRP6a_client_method())
		#logging.debug(asrp.contents)
		
		# define o nome de usuário
		logging.debug("SRP_set_username: {0}".format(AppleSRP.SRP_set_username(asrp, username.encode('utf-8'))))
		#logging.debug(asrp.contents)
		
		# define os parâmetros do servidor
		logging.debug("SRP_set_params: {0}".format(AppleSRP.SRP_set_params(asrp, n, len(n), g, len(g), salt, len(salt))))
		#logging.debug(asrp.contents)
		
		# gera a chave pública
		client_gen_pubkey_ptr = AppleSRP.cstr_new()
		logging.debug("SRP_gen_pub: {0}".format(AppleSRP.SRP_gen_pub(asrp, ctypes.byref(client_gen_pubkey_ptr))))
		client_gen_pubkey = client_gen_pubkey_ptr.contents
		logging.debug(client_gen_pubkey)
		#logging.debug(asrp.contents)

		# define a senha
		password_bytes = self.password.encode('utf-8')
		logging.debug("SRP_set_auth_password: {0}".format(AppleSRP.SRP_set_auth_password(asrp, password_bytes, len(password_bytes))))
		#logging.debug(asrp.contents)
		
		# calcula a chave
		client_computed_key_ptr = AppleSRP.cstr_new()
		logging.debug("SRP_compute_key: {0}".format(AppleSRP.SRP_compute_key(asrp, ctypes.byref(client_computed_key_ptr), server_pkey, len(server_pkey))))
		client_computed_key = client_computed_key_ptr.contents
		logging.debug(client_computed_key)
		client_computed_key_buf = client_computed_key.get_data_buffer()
		#logging.debug(asrp.contents)
		
		# gera a resposta ao desafio
		client_proof_ptr = AppleSRP.cstr_new()
		logging.debug("SRP_respond: {0}".format(AppleSRP.SRP_respond(asrp, ctypes.byref(client_proof_ptr))))
		client_proof = client_proof_ptr.contents
		logging.debug(client_proof)
		#logging.debug(asrp.contents)
		
		client_iv = os.urandom(0x10)
		client_pkey = client_gen_pubkey.get_data_buffer()
		client_proof = client_proof.get_data_buffer()
		
		dic = OrderedDict([(u"iv", client_iv), (u"publicKey", client_pkey), (u"state", 3), (u"response", client_proof)])
		payload = CFLBinaryPListComposer.compose(dic)
		raw_message = ACPMessage.compose_auth_command(4, payload)
		self.send(raw_message)
		
		raw_reply_header = self.recv_message_header()
		reply_header = ACPMessage.parse_raw(raw_reply_header)
		
		if reply_header.error_code != 0:
			logging.debug("código de erro na autenticação: {0:#x}".format(reply_header.error_code))
			#XXX: blah, o que fazer...
			return
		
		logging.debug("recv_size: {0}".format(reply_header.body_size))
		raw_message = self.recv(reply_header.body_size)
		logging.debug("raw_message: {0!r}".format(raw_message))
		params2 = CFLBinaryPListParser.parse(raw_message)
		logging.debug(params2)
	
		server_proof = params2[u"response"]
		server_iv = params2[u"iv"]
		
		# verifica a resposta do servidor
		logging.debug("SRP_verify: {0}".format(AppleSRP.SRP_verify(asrp, server_proof, len(server_proof))))
		#logging.debug(asrp.contents)
		
		# limpeza
		logging.debug("Liberando cstr(s)")
		AppleSRP.cstr_free(client_gen_pubkey_ptr)
		AppleSRP.cstr_free(client_computed_key_ptr)
		AppleSRP.cstr_free(client_proof_ptr)
		logging.debug("SRP_free: {0}".format(AppleSRP.SRP_free(asrp)))
		
		###self.session.enable_encryption(client_computed_key_buf, client_iv, server_iv)

