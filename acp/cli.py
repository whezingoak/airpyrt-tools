import argparse
import binascii
import logging
import os.path
import sys
import time

from collections import OrderedDict

from .basebinary import *
from .client import ACPClient
from .exception import *
from .property import ACPProperty


class _ArgParser(argparse.ArgumentParser):
	def error(self, message):
		sys.stderr.write("error: {0}\n".format(message))
		#self.print_help()
		sys.exit(2)


def _cmd_not_implemented(*unused):
	raise ACPCommandLineError("manipulador de comando não implementado")

def _cmd_listprop(unused):
	print("\nPropriedades suportadas:\n")
	prop_names = ACPProperty.get_supported_property_names()
	for name in prop_names:
		print("{0}: {1}".format(name, ACPProperty.get_property_info_string(name, "description")))
	print()

def _cmd_helpprop(args):
	prop_name = args.pop()
	description = ACPProperty.get_property_info_string(prop_name, "description")
	prop_type = ACPProperty.get_property_info_string(prop_name, "type")
	validation = ACPProperty.get_property_info_string(prop_name, "validation")
	s = "{0} ({1}".format(description, prop_type)
	if validation:
		s += ", {0})".format(validation)
	else:
		s += ")"
	print(s)

def _cmd_getprop(client, args):
	prop_name = args.pop()
	prop = client.get_properties([prop_name])
	if len(prop):
		print(ACPProperty(prop_name, prop[0].value))

def _cmd_setprop(client, args):
	prop_name, prop_value = args
	prop_type = ACPProperty.get_property_info_string(prop_name, "type")
	prop = ACPProperty()
	if prop_type == "dec":
		try:
			prop = ACPProperty(prop_name, int(prop_value))
		except ValueError:
			logging.error("o valor para \"{0}\" tem o tipo errado, deveria ser {0}".format(prop_name, prop_type))
	elif prop_type == "hex":
		try:
			#XXX: esta não é a maneira correta de lidar com exceções
			prop = ACPProperty(prop_name, int(prop_value, 16))
		except ValueError:
			logging.error("o valor para \"{0}\" tem o tipo errado, deveria ser {0}".format(prop_name, prop_type))
	elif prop_type == "mac":
		#XXX: não estamos tratando nossa exceção
		prop = ACPProperty(prop_name, prop_value)
	elif prop_type == "bin":
		prop = ACPProperty(prop_name, binascii.unhexlify(prop_value))
	elif prop_type == "str":
		prop = ACPProperty(prop_name, prop_value)
	elif prop_type in ["cfb", "log"]:
		logging.error("tipo de propriedade não suportado: {0}".format(prop_type))
	client.set_properties({prop_name : prop})

def _cmd_dumpprop(client, unused):
	prop_names = ACPProperty.get_supported_property_names()
	properties = client.get_properties(prop_names)
	for prop in properties:
		padded_description = ACPProperty.get_property_info_string(prop.name, "description").ljust(32, " ")
		print("{0}: {1}".format(padded_description, prop))

def _cmd_acpprop(client, unused):
	props_reply = client.get_properties(["prop"])
	props_raw = props_reply[0].value
	props = ""
	for i in range(len(props_raw) / 4):
		props += "{0}\n".format(props_raw[i*4:i*4+4])
	print(props)

def _cmd_dump_syslog(client, unused):
	print("{0}".format(client.get_properties(["logm"])[0]))

def _cmd_reboot(client, unused):
	print("Reiniciando o dispositivo")
	client.set_properties({"acRB" : ACPProperty("acRB", 0)})

def _cmd_factory_reset(client, unused):
	print("Executando a redefinição de fábrica")
	client.set_properties(OrderedDict([("acRF",ACPProperty("acRF", 0)), ("acRB",ACPProperty("acRB", 0))]))

def _cmd_flash_primary(client, args):
	fw_path = args.pop()
	if os.path.exists(fw_path):
		with open(fw_path, "rb") as fw_file:
			fw_data = fw_file.read()
		print("Gravando a partição primária do firmware")
		client.flash_primary(fw_data)
	else:
		logging.error("O arquivo basebinary não pôde ser lido no caminho: {0}".format(fw_path))

def _cmd_do_feat_command(client, unused):
	print(client.get_features())

def _cmd_decrypt(args):
	(inpath, outpath) = args
	with open(inpath, "rb") as infile:
		indata = infile.read()
	
	#XXX: preguiçoso, corrigir
	try:
		outdata = Basebinary.parse(indata)
	except BasebinaryError:
		raise
	else:
		with open(outpath, "wb") as outfile:
			outfile.write(outdata)

def _cmd_extract(args):
	(inpath, outpath) = args
	with open(inpath, "rb") as infile:
		indata = infile.read()
	
	#XXX: preguiçoso, corrigir
	try:
		outdata = Basebinary.extract(indata)
	except BasebinaryError:
		raise
	else:
		with open(outpath, "wb") as outfile:
			outfile.write(outdata)

def _cmd_srp_test(client, unused):
	print("Testando SRP")
	client.authenticate_AppleSRP()
	client.close()


def main():
	#TODO: adicionar argumento de CLI para verbosidade
	logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)
	
	parser = _ArgParser()
	
	parameters_group = parser.add_argument_group("Parâmetros do cliente AirPort")
	parameters_group.add_argument("-t", "--target", metavar="address", help="Endereço IP ou hostname do roteador alvo")
	parameters_group.add_argument("-p", "--password", metavar="password", help="Senha de administrador do roteador")
	
	airport_client_group = parser.add_argument_group("Comandos do cliente AirPort")
	airport_client_group.add_argument("--listprop", action="store_const", const=True, help="lista as propriedades suportadas")
	airport_client_group.add_argument("--helpprop", metavar="property", nargs=1, help="imprime a descrição da propriedade especificada")
	airport_client_group.add_argument("--getprop", metavar="property", nargs=1, help="obtém o valor da propriedade especificada")
	airport_client_group.add_argument("--setprop", metavar=("property", "value"), nargs=2, help="define o valor da propriedade especificada")
	airport_client_group.add_argument("--dumpprop", action="store_const", const=True, help="exibe os valores de todas as propriedades suportadas")
	airport_client_group.add_argument("--acpprop", action="store_const", const=True, help="obtém a lista acp acpprop")
	airport_client_group.add_argument("--dump-syslog", action="store_const", const=True, help="exibe o log de sistema do roteador")
	airport_client_group.add_argument("--reboot", action="store_const", const=True, help="reinicia o dispositivo")
	airport_client_group.add_argument("--factory-reset", action="store_const", const=True, help="RESETA TUDO e reinicia; você foi avisado!")
	airport_client_group.add_argument("--flash-primary", metavar="firmware_path", nargs=1, help="flasheia o firmware da partição primária")
	airport_client_group.add_argument("--do-feat-command", action="store_const", const=True, help="envia o comando 0x1b (feat)")
	
	basebinary_group = parser.add_argument_group("Comandos de basebinary")
	basebinary_group.add_argument("--decrypt", metavar=("inpath", "outpath"), nargs=2, help="descriptografa o basebinary")
	basebinary_group.add_argument("--extract", metavar=("inpath", "outpath"), nargs=2, help="extrai o conteúdo do gzimg")
	
	test_group = parser.add_argument_group("Argumentos de teste")
	test_group.add_argument("--srp-test", action="store_const", const=True, help="SRP (requer macOS)")
	
	args_dict = vars(parser.parse_args())
	
	#TODO: dar a cada elemento um dict contendo os requisitos de parâmetro/informações do argparse, e então gerar o parser com base nisso
	commands = {
		"listprop": "local",
		"helpprop": "local",
		"getprop": "remote_admin",
		"setprop": "remote_admin",
		"dumpprop": "remote_admin",
		"acpprop": "remote_admin",
		"dump_syslog": "remote_admin",
		"reboot": "remote_admin",
		"factory_reset": "remote_admin",
		"flash_primary": "remote_admin",
		"do_feat_command": "remote_noauth",
		"decrypt": "local",
		"extract": "local",
		"srp_test": "remote_admin",
		}
	
	target = args_dict["target"]
	password = args_dict["password"]
	command_args = {k: v for k, v in args_dict.items() if k in commands and v is not None}
	
	if len(command_args) == 0:
		logging.error("é necessário especificar um comando")
		
	elif len(command_args) == 1:
		#TODO: limpar um pouco isso
		cmd, arg = command_args.popitem()
		assert commands[cmd] in ["local", "remote_noauth", "remote_admin"], "tipo de comando desconhecido \"{0}\"".format(commands[cmd])
		cmd_handler_name = "_cmd_{0}".format(cmd)
		cmd_handler = globals().get(cmd_handler_name, _cmd_not_implemented)
		
		if commands[cmd] == "local":
			cmd_handler(arg)
		
		if commands[cmd] == "remote_noauth":
			if target is not None:
				c = ACPClient(target)
				c.connect()
				cmd_handler(c, arg)
				c.close()
			else:
				logging.error("é necessário especificar um alvo")
		
		if commands[cmd] == "remote_admin":
			if target is not None and password is not None:
				c = ACPClient(target, password)
				c.connect()
				cmd_handler(c, arg)
				c.close()
			else:
				logging.error("é necessário especificar um alvo e a senha de administrador")
				
	else:
		logging.error("múltiplos comandos não são suportados, escolha apenas um")
