import binascii
import logging
import pprint
import struct

from .cflbinary import CFLBinaryPListParser
from .exception import ACPPropertyError


_acp_properties = [
	# Descomente e preencha os campos relevantes para adicionar suporte a uma propriedade
	# As propriedades devem estar no seguinte formato:
	# (nome, tipo, descricao, validacao), onde
	# nome (obrigatório) é uma string de 4 caracteres,
	# tipo (obrigatório) é um tipo de propriedade válido (str, dec, hex, log, mac, cfb, bin)
	# descricao (obrigatório) é uma descrição curta de uma linha da propriedade
	# validacao (opcional) é avaliada com eval() para verificar o valor de entrada ao definir uma propriedade
	("buil","str","String de Build?",""),
	("DynS","cfb","DNS",""),
	#("cfpf","","",""),
	#("cloC","","",""),
	#("cloD","","",""),
	#("conf","","",""),
	("fire","cfb","Firewall???",""),
	#("prob","","",""),
	("srcv","str","Source Version",""),
	("syNm","str","Nome do dispositivo",""),
	#("syDN","","",""),
	#("syPI","","",""),
	("syPW","str","Senha de administração do roteador",""),
	("syPR","str","String syPR???",""),
	("syGP","str","Senha de convidado do roteador???",""),
	#("syCt","","",""),
	#("syLo","","",""),
	("syDs","str","Descrição do sistema",""),
	("syVs","str","Versão do sistema",""),
	("syVr","str","Versão do sistema???",""),
	("syIn","str","Informações do sistema???",""),
	("syFl","hex","????",""),
	("syAM","str","Identificador do modelo",""),
	("syAP","dec","ID do produto",""),
	("sySN","str","Número de série da Apple",""),
	#("ssSN","","",""),
	#("sySK","","",""),
	("ssSK","str","SKU da Apple",""),
	#("syRe","","",""),
	("syLR","cfb","Blob syLR",""),
	("syAR","cfb","Blob syAR",""),
	("syUT","dec","Tempo de atividade do sistema",""),
	#("minV","","",""),
	("minS","str","apple-minver",""),
	("chip","str","Descrição do SoC",""),
	#("card","","",""),
	#("memF","","",""),
	#("pool","","",""),
	#("tmpC","","",""),
	#("RPMs","","",""),
	("sySI","cfb","System Info Blob?",""),
	#("fDCY","","",""),
	("TMEn","hex","TMEn???",""),
	("CLTM","cfb","CLTM???",""),
	#("sPLL","","",""),
	#("syTL","","",""),
	#("syST","","",""),
	("sySt","cfb","Status do sistema",""),
	#("syIg","","",""),
	("syBL","str","String de versão do bootloader",""),
	("time","dec","Hora do sistema",""),
	("timz","cfb","Blob de configuração de fuso horário",""),
	("usrd","cfb","usrd???",""),
	#("uuid","","",""),
	#("drTY","","",""),
	#("sttE","","",""),
	#("sttF","","",""),
	#("stat","","",""),
	#("sRnd","","",""),
	#("Accl","","",""),
	("dSpn","cfb","Status de rotação do disco?",""),
	("syMS","str","Número de série da MLB",""),
	#("IGMP","","",""),
	("diag","bin","diag???",""),
	#("paFR","","",""),
	("raNm","str","Nome do rádio",""),
	#("raCl","","",""),
	#("raSk","","",""),
	#("raWM","","",""),
	#("raEA","","",""),
	#("raWE","","",""),
	#("raCr","","",""),
	#("raKT","","",""),
	#("raNN","","",""),
	#("raGK","","",""),
	#("raHW","","",""),
	#("raCM","","",""),
	#("raRo","","",""),
	#("raCA","","",""),
	#("raCh","","",""),
	#("rCh2","","",""),
	#("raWC","","",""),
	#("raDe","","",""),
	#("raMu","","",""),
	#("raLC","","",""),
	#("raLF","","",""),
	#("ra1C","","",""),
	#("raVs","","",""),
	("raMA","mac","Endereço MAC do rádio",""),
	#("raM2","","",""),
	#("raMO","","",""),
	#("raLO","","",""),
	#("raDS","","",""),
	#("raNA","","",""),
	#("raWB","","",""),
	#("raIS","","",""),
	#("raMd","","",""),
	#("raPo","","",""),
	#("raPx","","",""),
	#("raTr","","",""),
	#("raDt","","",""),
	#("raFC","","",""),
	#("raEC","","",""),
	#("raMX","","",""),
	#("raIE","","",""),
	#("raII","","",""),
	#("raB0","","",""),
	#("raB1","","",""),
	#("raB2","","",""),
	#("raSt","","",""),
	#("APSR","","",""),
	#("raTX","","",""),
	#("raRX","","",""),
	#("raAC","","",""),
	("raSL","cfb","Lista de rádios?",""),
	#("raMI","","",""),
	#("raST","","",""),
	#("raDy","","",""),
	#("raEV","","",""),
	#("rTSN","","",""),
	("raSR","cfb","Resultados da varredura de rádio?",""),
	#("eaRA","","",""),
	("WiFi","cfb","Configuração do Wifi?",""),
	("rCAL","cfb","Dados de calibração do rádio?",""),
	#("moPN","","",""),
	#("moAP","","",""),
	#("moUN","","",""),
	#("moPW","","",""),
	#("moIS","","",""),
	#("moLS","","",""),
	#("moLI","","",""),
	#("moID","","",""),
	#("moDT","","",""),
	#("moPD","","",""),
	#("moAD","","",""),
	#("moCC","","",""),
	#("moCR","","",""),
	#("moCI","","",""),
	#("^moM","","",""),
	#("moVs","","",""),
	#("moMP","","",""),
	#("moMF","","",""),
	#("moFV","","",""),
	#("pdFl","","",""),
	#("pdUN","","",""),
	#("pdPW","","",""),
	#("pdAR","","",""),
	#("pdID","","",""),
	#("pdMC","","",""),
	#("peSN","","",""),
	#("peUN","","",""),
	#("pePW","","",""),
	#("peSC","","",""),
	#("peAC","","",""),
	#("peID","","",""),
	#("peAO","","",""),
	("waCV","bin","Modo de configuração da WAN?",""),
	("waIn","bin","Modo de interface da WAN?",""),
	#("waD1","","",""),
	#("waD2","","",""),
	#("waD3","","",""),
	#("waC1","","",""),
	#("waC2","","",""),
	#("waC3","","",""),
	("waIP","bin","IP da WAN",""),
	#("waSM","","",""),
	("waRA","bin","IP do gateway upstream da WAN",""),
	#("waDC","","",""),
	#("waDS","","",""),
	("waMA","mac","Endereço MAC da WAN",""),
	#("waMO","","",""),
	#("waDN","","",""),
	#("waCD","","",""),
	#("waIS","","",""),
	#("waNM","","",""),
	#("waSD","","",""),
	#("waFF","","",""),
	#("waRO","","",""),
	#("waW1","","",""),
	#("waW2","","",""),
	#("waW3","","",""),
	#("waLL","","",""),
	#("waUB","","",""),
	("waDI","cfb","Informações DHCP da WAN?",""),
	#("laCV","","",""),
	#("laIP","","",""),
	#("laSM","","",""),
	#("laRA","","",""),
	#("laDC","","",""),
	#("laDS","","",""),
	#("laNA","","",""),
	("laMA","mac","Endereço MAC da LAN",""),
	#("laIS","","",""),
	#("laSD","","",""),
	#("laIA","","",""),
	#("gn6?","","",""),
	#("gn6A","","",""),
	#("gn6P","","",""),
	#("dhFl","","",""),
	#("dhBg","","",""),
	#("dhEn","","",""),
	#("dhSN","","",""),
	#("dhRo","","",""),
	#("dhLe","","",""),
	#("dhMg","","",""),
	#("dh95","","",""),
	("DRes","cfb","Reservas DHCP",""),
	#("dhWA","","",""),
	#("dhDS","","",""),
	#("dhDB","","",""),
	#("dhDE","","",""),
	#("dhDL","","",""),
	("dhSL","cfb","Concessões do servidor DHCP?",""),
	#("gnFl","","",""),
	#("gnBg","","",""),
	#("gnEn","","",""),
	#("gnSN","","",""),
	#("gnRo","","",""),
	#("gnLe","","",""),
	#("gnMg","","",""),
	#("gn95","","",""),
	#("gnDi","","",""),
	#("naFl","","",""),
	#("naBg","","",""),
	#("naEn","","",""),
	#("naSN","","",""),
	#("naRo","","",""),
	#("naAF","","",""),
	#("nDMZ","","",""),
	#("pmPI","","",""),
	#("pmPS","","",""),
	#("pmPR","","",""),
	#("pmTa","","",""),
	#("acEn","","",""),
	#("acTa","","",""),
	("tACL","cfb","Controle de Acesso Temporizado",""),
	#("wdFl","","",""),
	#("wdLs","","",""),
	#("dWDS","","",""),
	#("cWDS","","",""),
	#("dwFl","","",""),
	#("raFl","","",""),
	#("raI1","","",""),
	#("raTm","","",""),
	#("raAu","","",""),
	#("raAc","","",""),
	#("raSe","","",""),
	#("raRe","","",""),
	#("raF2","","",""),
	#("raI2","","",""),
	#("raT2","","",""),
	#("raU2","","",""),
	#("raC2","","",""),
	#("raS2","","",""),
	#("raR2","","",""),
	#("raCi","","",""),
	("ntSV","str","Hostname do servidor NTP",""),
	#("ntpC","","",""),
	#("smtp","","",""),
	#("slog","","",""),
	#("slgC","","",""),
	#("slCl","","",""),
	("slvl","dec","Nível de severidade do log do sistema?",""),
	#("slfl","","",""),
	("logm","log","Dados do log do sistema",""),
	#("snAF","","",""),
	#("snLW","","",""),
	#("snLL","","",""),
	#("snRW","","",""),
	#("snWW","","",""),
	#("snRL","","",""),
	#("snWL","","",""),
	#("snCS","","",""),
	#("srtA","","",""),
	#("srtF","","",""),
	#("upsF","","",""),
	#("usbF","","",""),
	("USBi","cfb","Informações do USB",""),
	#("USBL","","",""),
	#("USBR","","",""),
	#("USBO","","",""),
	#("USBs","","",""),
	#("USBo","","",""),
	#("USBh","","",""),
	#("USBb","","",""),
	#("USBn","","",""),
	("prni","cfb","Informações da impressora?",""),
	#("prnM","","",""),
	#("prnI","","",""),
	#("prnR","","",""),
	#("RUdv","","",""),
	#("RUfl","","",""),
	("MaSt","cfb","Informações de armazenamento em massa USB",""),
	#("SMBw","","",""),
	#("SMBs","","",""),
	#("fssp","","",""),
	#("diSD","","",""),
	#("diCS","","",""),
	#("deSt","","",""),
	#("daSt","","",""),
	#("dmSt","","",""),
	#("adNm","","",""),
	#("adBD","","",""),
	#("adAD","","",""),
	#("adHU","","",""),
	#("IDNm","","",""),
	("seFl","bin","????",""), #????
	#("nvVs","","",""),
	#("dbRC","","",""),
	("dbug","hex","Flags de depuração","0 <= value <= 0xFFFFFFFF"),
	#("dlvl","","",""),
	#("dcmd","","",""),
	#("dsps","","",""),
	#("logC","","",""),
	#("cver","","",""),
	("ctim","hex","ctim???",""),
	#("svMd","","",""),
	#("serM","","",""),
	#("serT","","",""),
	#("emNo","","",""),
	#("effF","","",""),
	#("LLnk","","",""),
	#("WLnk","","",""),
	#("PHYS","","",""),
	#("PHYN","","",""),
	#("Rnfo","","",""),
	#("evtL","","",""),
	#("isAC","","",""),
	#("Adet","","",""),
	("Prof","cfb","Blob de restauração de perfil",""),
	#("maAl","","",""),
	#("maPr","","",""),
	#("leAc","","",""),
	#("APID","","",""),
	#("AAU ","","",""),
	("lcVs","str","String de versão lcVs?",""),
	#("lcVr","","",""),
	#("lcmV","","",""),
	#("lcMV","","",""),
	#("iMTU","","",""),
	("wsci","cfb","Blob wsci",""),
	#("FlSu","","",""),
	("OTPR","hex","machdep.otpval",""),
	("acRB","dec","Flag de reinicialização do dispositivo","value == 0"),
	("acRI","dec","Recarregar serviços??","value == 0"),
	#("acPC","","",""),
	#("acDD","","",""),
	#("acPD","","",""),
	#("acPG","","",""),
	#("acDS","","",""),
	#("acFN","","",""),
	#("acRP","","",""),
	("acRN","dec","Reseta algo... (?)","value == 0"),
	("acRF","dec","Redefinir para padrões de fábrica","value == 0"),
	#("MdmH","","",""),
	#("dirf","","",""),
	#("Afrc","","",""),
	#("lebl","","",""),
	#("lebs","","",""),
	("LEDc","dec","Cor/padrão do LED","0 <= value <= 3"),
	#("acEf","","",""),
	#("invr","","",""),
	#("FLSH","","",""),
	#("acPL","","",""),
	#("rReg","","",""),
	#("dReg","","",""),
	("GPIs","bin","Valores de GPIOs","len(value) == 8"),
	#("play","","",""),
	#("paus","","",""),
	#("ffwd","","",""),
	#("rwnd","","",""),
	#("itun","","",""),
	#("plls","","",""),
	#("User","","",""),
	#("Pass","","",""),
	#("itIP","","",""),
	#("itpt","","",""),
	#("daap","","",""),
	#("song","","",""),
	#("arti","","",""),
	#("albm","","",""),
	#("volm","","",""),
	#("rvol","","",""),
	#("Tcnt","","",""),
	#("Bcnt","","",""),
	#("shfl","","",""),
	#("rept","","",""),
	#("auPr","","",""),
	#("auJD","","",""),
	#("auNN","","",""),
	#("auNP","","",""),
	#("aFrq","","",""),
	#("aChn","","",""),
	#("aLvl","","",""),
	#("aPat","","",""),
	#("aSta","","",""),
	#("aStp","","",""),
	#("auCC","","",""),
	#("acmp","","",""),
	#("aenc","","",""),
	#("anBf","","",""),
	#("aWan","","",""),
	#("auRR","","",""),
	#("auMt","","",""),
	#("aDCP","","",""),
	#("DCPc","","",""),
	#("DACP","","",""),
	#("DCPi","","",""),
	#("auSl","","",""),
	#("auFl","","",""),
	("fe01","hex","????",""),
	("feat","str","Recursos suportados?",""),
	("prop","str","Propriedades acp válidas",""),
	("hw01","hex","????",""),
	#("fltr","","",""),
	#("wdel","","",""),
	#("plEB","","",""),
	#("rWSC","","",""),
	#("uDFS","","",""),
	#("dWPA","","",""),
	#("dpFF","","",""),
	#("duLF","","",""),
	#("ieHT","","",""),
	#("dwlX","","",""),
	#("dd11","","",""),
	#("dRdr","","",""),
	#("dotD","","",""),
	#("dotH","","",""),
	#("dPwr","","",""),
	#("wlBR","","",""),
	#("iTIM","","",""),
	#("idAG","","",""),
	#("mvFL","","",""),
	#("mvFM","","",""),
	#("dPPP","","",""),
	#("!mta","","",""),
	#("minR","","",""),
	#("SpTr","","",""),
	#("dRBT","","",""),
	#("dRIR","","",""),
	("pECC","cfb","Blob ECC do PCIe?",""),
	#("fxEB","","",""),
	#("fxID","","",""),
	#("fuup","","",""),
	#("fust","","",""),
	#("fuca","","",""),
	("fugp","str","Progresso da atualização de firmware",""),
	("cks0","hex","Checksum do Flash do Bootloader",""),
	("cks1","hex","Checksum do Flash Primário",""),
	("cks2","hex","Checksum do Flash Secundário",""),
	#("ddBg","","",""),
	#("ddEn","","",""),
	#("ddIn","","",""),
	#("ddSm","","",""),
	#("ddEC","","",""),
	#("ddFE","","",""),
	#("ddSR","","",""),
	#("6cfg","","",""),
	#("6aut","","",""),
	#("6Qpd","","",""),
	#("6Wad","","",""),
	#("6Wfx","","",""),
	#("6Wgw","","",""),
	#("6Wte","","",""),
	#("6Lfw","","",""),
	#("6Lad","","",""),
	#("6Lfx","","",""),
	#("6sfw","","",""),
	#("6pmp","","",""),
	#("6trd","","",""),
	#("6sec","","",""),
	#("6fwl","","",""),
	#("6NS1","","",""),
	#("6NS2","","",""),
	#("6NS3","","",""),
	#("6ahr","","",""),
	#("6dhs","","",""),
	#("6dso","","",""),
	#("6PDa","","",""),
	#("6PDl","","",""),
	#("6vlt","","",""),
	#("6plt","","",""),
	#("6CWa","","",""),
	#("6CWp","","",""),
	#("6CWg","","",""),
	#("6CLa","","",""),
	#("6NSa","","",""),
	#("6NSb","","",""),
	#("6NSc","","",""),
	#("6CPa","","",""),
	#("6CPl","","",""),
	#("6!at","","",""),
	("rteI","cfb","rteI Blob",""),
	#("PCLI","","",""),
	#("dxEM","","",""),
	#("dxID","","",""),
	#("dxAI","","",""),
	#("dxIP","","",""),
	#("dxOA","","",""),
	#("dxIA","","",""),
	#("dxC1","","",""),
	#("dxP1","","",""),
	#("dxC2","","",""),
	#("dxP2","","",""),
	#("bjFl","","",""),
	#("bjSd","","",""),
	#("bjSM","","",""),
	#("wbEn","","",""),
	#("wbHN","","",""),
	#("wbHU","","",""),
	#("wbHP","","",""),
	#("wbRD","","",""),
	#("wbRU","","",""),
	#("wbRP","","",""),
	#("wbAC","","",""),
	#("dMac","","",""),
	#("iCld","","",""),
	#("iCLH","","",""),
	#("iCLB","","",""),
	#("SUEn","","",""),
	#("SUAI","","",""),
	#("SUFq","","",""),
	#("SUSv","","",""),
	#("suPR","","",""),
	#("msEn","","",""),
	#("trCo","","",""),
	#("EZCF","","",""),
	#("ezcf","","",""),
	#("gVID","","",""),
	#("wcfg","","",""),
	#("awce","","",""),
	#("wcgu","","",""),
	#("wcgs","","",""),
	#("awcc","","",""),
	]

def _generate_acp_property_dict():	
	props = {}
	for (name, type, description, validation) in _acp_properties:
		# validação básica das tuplas
		assert len(name) == 4, "nome inválido na lista _acp_properties: {0}".format(name)
		assert type in ["str", "dec", "hex", "log", "mac", "cfb", "bin"], "tipo inválido na lista _acp_properties para o nome: {0}".format(name)
		assert description, "descrição ausente na lista _acp_properties para o nome: {0}".format(name)
		props[name] = dict(type=type, description=description, validation=validation)
	return props


class ACPPropertyInitValueError(ACPPropertyError):
	pass


class ACPProperty(object):
	_acpprop = _generate_acp_property_dict()
	
	_element_header_format = struct.Struct("!4s2I")
	element_header_size = _element_header_format.size
	
	
	def __init__(self, name=None, value=None):
		# lida primeiro com o nome e valor da propriedade "nula" empacotada
		if name == b"\x00\x00\x00\x00" and value == b"\x00\x00\x00\x00":
			name = None
			value = None
		
		if name and name not in self.get_supported_property_names():
			raise ACPPropertyError("nome de propriedade inválido passado para o inicializador: {0}".format(name))
		
		if value is not None:
			# aceita o valor como uma string binária empacotada ou tipo Python
			prop_type = self.get_property_info_string(name, "type")
			_init_handler_name = "_init_{0}".format(prop_type)
			assert hasattr(self, _init_handler_name), "manipulador de inicialização ausente para o tipo de propriedade \"{0}\"".format(prop_type)
			_init_handler = getattr(self, _init_handler_name)
			
			logging.debug("valor antigo: {0!r} tipo: {1}".format(value, type(value)))
			try:
				value = _init_handler(value)
			except ACPPropertyInitValueError as e:
				raise ACPPropertyError("{0!s} fornecido para o tipo de propriedade \"{1}\": {2!r}".format(e, prop_type, value))
			logging.debug("novo valor: {0!r} tipo: {1}".format(value, type(value)))
			
			#XXX: isso ainda é muito gambiarra, provavelmente deveria fazer algo com funções anônimas ou introspecção
			validation_expr = self.get_property_info_string(name, "validation")
			if validation_expr and not eval(validation_expr):
				raise ACPPropertyError("valor inválido passado para o inicializador da propriedade \"{0}\": {1}".format(name, repr(value)))
		
		self.name = name
		self.value = value
	
	def _init_dec(self, value):
		if   isinstance(value, int):
			return value
		elif isinstance(value, bytes):
			try:
				return struct.unpack("!I", value)[0]
			except:
				raise ACPPropertyInitValueError("string binária empacotada inválida")
		else:
			raise ACPPropertyInitValueError("tipo embutido inválido")
	
	def _init_hex(self, value):
		if   isinstance(value, int):
			return value
		elif isinstance(value, bytes):
			try:
				return struct.unpack("!I", value)[0]
			except:
				raise ACPPropertyInitValueError("string binária empacotada inválida")
		else:
			raise ACPPropertyInitValueError("tipo embutido inválido")
	
	def _init_mac(self, value):
		if isinstance(value, bytes):
			# valor binário empacotado
			if len(value) == 6:
				return value
			else:
				raise ACPPropertyInitValueError("valor de bytes empacotado inválido")
		elif isinstance(value, str):
			# valor delimitado por dois pontos
			mac_bytes = value.split(":")
			if len(mac_bytes) == 6:
				try:
					return binascii.unhexlify("".join(mac_bytes))
				except binascii.Error:
					raise ACPPropertyInitValueError("dígito não hexadecimal no valor")
			# fallthrough
			raise ACPPropertyInitValueError("valor de string inválido")
		else:
			raise ACPPropertyInitValueError("tipo embutido inválido")
	
	def _init_bin(self, value):
		if isinstance(value, bytes):
			return value
		elif isinstance(value, str):
			return value.encode('utf-8') # Assuming UTF-8 for strings from user
		else:
			raise ACPPropertyInitValueError("tipo embutido inválido")
	
	def _init_cfb(self, value):
		if isinstance(value, bytes):
			return value
		else:
			raise ACPPropertyInitValueError("tipo embutido inválido")
	
	def _init_log(self, value):
		if isinstance(value, bytes):
			return value
		else:
			raise ACPPropertyInitValueError("tipo embutido inválido")
	
	def _init_str(self, value):
		if isinstance(value, str):
			return value
		elif isinstance(value, bytes):
			return value.decode('utf-8').rstrip('\x00')
		else:
			raise ACPPropertyInitValueError("tipo embutido inválido")
	
	
	def __repr__(self):
		#XXX: return tuple or dict?
		return repr((self.name, self.value))
	
	
	#TODO: fazer esta função retornar algo diferente do valor formatado da propriedade... continuo me confundindo com a sua ruindade atual
	def __str__(self):
		#XXX: isso é a coisa certa a se fazer?
		if self.name is None or self.value is None:
			return ""
		
		prop_type = self.get_property_info_string(self.name, "type")
		_format_handler_name = "_format_{0}".format(prop_type)
		assert hasattr(self, _format_handler_name), "manipulador de formato ausente para o tipo de propriedade \"{0}\"".format(prop_type)
		return getattr(self, _format_handler_name)(self.value)
	
	def _format_dec(self, value):
		return str(value)
	
	def _format_hex(self, value):
		return hex(value)
	
	def _format_mac(self, value):
		return ":".join("{:02x}".format(b) for b in value)
	
	def _format_bin(self, value):
		return binascii.hexlify(value).decode('ascii')
	
	def _format_cfb(self, value):
		return pprint.pformat(CFLBinaryPListParser.parse(value))
	
	def _format_log(self, value):
		# Assuming the log is latin-1 or some other 8-bit encoding.
		# It's definitely not UTF-8.
		return value.decode('latin-1').replace('\x00', '\n')
	
	def _format_str(self, value):
		return value
	
	
	@classmethod
	def get_supported_property_names(cls):
		props = []
		for name in cls._acpprop:
			props.append(name)
		return props
	
	
	@classmethod
	def get_property_info_string(cls, prop_name, key):
		#XXX: should we do this differently?
		if prop_name is None:
			return None
		if prop_name not in cls._acpprop:
			logging.error("property \"{0}\" not supported".format(prop_name))
			return None
		prop_info = cls._acpprop[prop_name]
		if key not in prop_info:
			logging.error("invalid property info key \"{0}\"".format(key))
			return None
		return prop_info[key]
	
	
	@classmethod
	def parse_raw_element(cls, data):
		name, flags, size = cls.parse_raw_element_header(data[:cls.element_header_size])
		#TODO: handle flags!???
		return cls(name, data[cls.element_header_size:])
	
	
	@classmethod
	def parse_raw_element_header(cls, data):
		try:
			return cls._element_header_format.unpack(data)
		except struct.error:
			raise ACPPropertyError("failed to parse property element header")
	
	
	@classmethod
	def compose_raw_element(cls, flags, property):
		#TODO: lidar com flags!???
		#XXX: lida primeiro com o nome ou valor "nulo", mas isso atualmente é lixo
		name = property.name.encode('ascii') if property.name is not None else b"\x00\x00\x00\x00"
		value = property.value

		if value is None:
			value = b"\x00\x00\x00\x00"

		if isinstance(value, int):
			st = struct.Struct(">I")
			#XXX: isso pode lançar uma exceção, ainda precisamos verificar o intervalo de valores int/hex para garantir que eles sejam empacotados em 32 bits
			return cls.compose_raw_element_header(name, flags, st.size) + st.pack(value)
		elif isinstance(value, str):
			# Assume string properties are UTF-8
			value_bytes = value.encode('utf-8')
			return cls.compose_raw_element_header(name, flags, len(value_bytes)) + value_bytes
		elif isinstance(value, bytes):
			return cls.compose_raw_element_header(name, flags, len(value)) + value
		else:
			raise ACPPropertyError("tipo de propriedade não tratado para composição de elemento bruto")
	
	
	@classmethod
	def compose_raw_element_header(cls, name, flags, size):
		try:
			return cls._element_header_format.pack(name, flags, size)
		except struct.error:
			raise ACPPropertyError("failed to compose property header")
