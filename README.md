# Ferramentas AirPyrt

### Licença

Veja o arquivo LICENSE.

### Requisitos

- Python 3.11
- pycryptodome

Em sistemas baseados em Debian (como o Debian 12 e o Ubuntu), você também precisará do pacote `setuptools` para a instalação. Você pode instalá-lo com o seguinte comando:
```bash
apt-get update && apt-get install python3-setuptools
```

### Compatibilidade

Este programa foi testado e funciona no **macOS** e **Debian 12**.

**Atenção:** A funcionalidade de autenticação SRP (`--srp-test`) depende de uma biblioteca nativa do macOS e, portanto, só funcionará em sistemas da Apple. Todas as outras funcionalidades do programa são compatíveis com Debian 12.

### Instalação

Para instalar as ferramentas no seu sistema (requer permissões de root/sudo):
```bash
python3 setup.py install
```

Se preferir instalar apenas para o seu usuário local (não requer root/sudo):
```bash
python3 setup.py install --user
```

### Uso

`python -m acp`

    usage: __main__.py [-h] [-t address] [-p password] [--listprop]
                       [--helpprop property] [--getprop property]
                       [--setprop property value] [--dumpprop] [--acpprop]
                       [--dump-syslog] [--reboot] [--factory-reset]
                       [--flash-primary firmware_path] [--do-feat-command]
                       [--decrypt inpath outpath] [--extract inpath outpath]
                       [--srp-test]

    Argumentos opcionais:
      -h, --help            mostra esta mensagem de ajuda e sai

    Parâmetros do cliente AirPort:
      -t address, --target address
                            Endereço IP ou hostname do roteador alvo
      -p password, --password password
                            Senha de administrador do roteador

    Comandos do cliente AirPort:
      --listprop            lista as propriedades suportadas
      --helpprop property   imprime a descrição da propriedade especificada
      --getprop property    obtém o valor da propriedade especificada
      --setprop property value
                            define o valor da propriedade especificada
      --dumpprop            exibe os valores de todas as propriedades suportadas
      --acpprop             obtém a lista acp acpprop
      --dump-syslog         exibe o log de sistema do roteador
      --reboot              reinicia o dispositivo
      --factory-reset       RESETA TUDO e reinicia; você foi avisado!
      --flash-primary firmware_path
                            flasheia o firmware da partição primária
      --do-feat-command     envia o comando 0x1b (feat)

    Comandos de basebinary:
      --decrypt inpath outpath
                            descriptografa o basebinary
      --extract inpath outpath
                            extrai o conteúdo do gzimg

    Argumentos de teste:
      --srp-test            SRP (requer macOS)


### Notas

**IMPORTANTE**

Esta ferramenta ainda usa a implementação antiga do protocolo ACP, que envia a senha de administrador do dispositivo pela rede em um formato facilmente recuperável. Isso foi corrigido no novo protocolo, que usa autenticação SRP e uma criptografia melhor para as requisições de e para o dispositivo. Até que isso seja implementado, esta ferramenta é totalmente insegura para uso, especialmente para administração remota (que você já deveria ter desabilitado de qualquer maneira...).

Este projeto cresceu organicamente a partir do meu entendimento de várias partes do protocolo ACP. Eu reestruturei o código algumas vezes à medida que ele melhorou, mas ainda existem muitas lacunas na implementação e muito "código fedorento". Entre guardar isso indefinidamente fazendo melhorias incrementais (e provavelmente nunca lançar um produto "acabado") e lançá-lo em um estado mais bruto para que outros possam explorar, a segunda opção fez muito mais sentido.

Um valor de retorno de `0xfffffff6` ao usar `--getprop` significa que a propriedade não está disponível/legível.


## TODO (lista muito incompleta e sem ordem particular)

- adicionar tipo de endereço IP para propriedades, garantindo suporte a IPv4 e IPv6
- especificar atributo RO/WO/RW para propriedades
- tratamento de exceções:
  - campos de struct inválidos não são bem tratados em muitos casos
  - terminar de adicionar classes de exceção personalizadas e garantir que estamos usando-as
- logging (quase pronto, mas ainda parece horrível) com controles de verbosidade
- revisar e atualizar docstrings
- suporte a SRP (corrigir o pysrp porque gambiarras com ctypes, embora divertidas, são horríveis e não portáteis)
- suporte ao protocolo ACP versão 2 (criptografia de sessão completa)
- lidar com elementos de propriedade criptografados
- reempacotamento/recriptografia do basebinary
- montagem do rootfs do basebinary
- servidor com threads
- lidar com o protocolo v1 (para firmwares/dispositivos antigos)
- anúncio/descoberta via Bonjour
- opções para especificar sem criptografia, método antigo e novo método (SRP)
- suporte a ACPMonitorSession
- suporte a ACPRPC
