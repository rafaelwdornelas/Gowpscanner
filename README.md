
# Gowpscanner

![Gowpscanner](https://raw.githubusercontent.com/rafaelwdornelas/Gowpscanner/refs/heads/main/Screenshot.png)

**Gowpscanner** é uma ferramenta desenvolvida em Go para escanear sites WordPress em busca de vulnerabilidades e configurações expostas.  
O scanner identifica se o site está servindo em HTTP/HTTPS, verifica se o CMS é WordPress (inclusive extraindo a versão), e realiza diversas checagens, como:

- Exposição de arquivos de configuração (ex.: backups de configuração, exportações de banco de dados, etc);
- Verificação de plugins e temas vulneráveis;
- Busca de shells e backdoors expostos;
- Extração de versões utilizando expressões regulares e heurísticas;
- Integração com um arquivo YAML dinâmico para definir, por exemplo, o caminho do arquivo README de cada plugin.

---

## Recursos

- **Atualização de Base de Dados:**  
  A ferramenta verifica/atualiza a base de dados de vulnerabilidades antes de iniciar o scan.

- **Criação Automática de Pastas de Retorno:**  
  São criados diretórios para armazenar logs de plugins, temas, versões e outras informações.

- **Escaneamento Concorrente:**  
  Utiliza goroutines com controle de concorrência para acelerar o processamento de vários domínios simultaneamente.

- **Output Formatado:**  
  Mensagens coloridas e formatadas são exibidas no terminal para facilitar a visualização dos resultados.

- **Integração com YAML Dinâmico:**  
  O arquivo `./database/dynamic_finders.yml` permite definir dinamicamente parâmetros, como o caminho do arquivo README de cada plugin. Caso não haja definição, é utilizado o padrão `readme.txt`.

---

## Pré-requisitos

- **Go:** Versão 1.16 ou superior  
- **Git:** Para clonar o repositório  
- **Dependências:** Gerenciadas via módulos do Go (go.mod)

Além disso, é necessário que os seguintes arquivos estejam presentes no diretório `./database`:

- `config_backups.txt`
- `db_exports.txt`
- `timthumbs-v3.txt`
- `plugins.txt`
- `themes.txt`
- `dynamic_finders.yml` (arquivo YAML para definições dinâmicas)

Obs: Esses arquivos são criados automaticamente, com a atualização automatica da base de dados de falhas.

Também é necessário um arquivo `dominios.txt` contendo os domínios a serem escaneados (um domínio por linha).

---

## Instalação

Clone o repositório e compile a ferramenta:

```bash
git clone https://github.com/rafaelwdornelas/Gowpscanner.git
cd Gowpscanner
go build -o gowpscanner
```

---

## Uso

Após a compilação, coloque a lista de dominios que quer verificar em dominios.txt e é só executar o scanner:

```bash
./gowpscanner
```

O fluxo da aplicação é o seguinte:

1. **Atualização da base de dados:**  
   A ferramenta verifica se a base de dados está atualizada ou a baixa, se necessário.

2. **Criação das pastas de retorno:**  
   São criadas pastas para armazenar os logs e os resultados dos scans.

3. **Escaneamento dos domínios:**  
   O scanner lê o arquivo `dominios.txt`, testa o acesso via HTTPS e HTTP, e identifica se o site utiliza WordPress. Caso positivo, realiza as checagens específicas (plugins, temas, configurações, shells, etc).

Os resultados são armazenados na pasta `./retornos`.

---

## Estrutura do Projeto

- **main.go:**  
  Ponto de entrada da aplicação.

- **internal/scanner:**  
  Contém a lógica principal do scanner:
  - `domain.go`: Verifica HTTP/HTTPS, detecta WordPress e inicia as verificações.
  - `plugins.go`: Realiza a checagem de plugins vulneráveis.
  - `themes.go`: Checa vulnerabilidades em temas.
  - `backups.go`: Procura arquivos de configuração expostos.
  - `timthumb.go`: Detecta vulnerabilidades relacionadas ao TimThumb.
  - `buscashell.go`: Verifica a presença de shells expostos.
  - `env.go`: Verifica a presença de arquivos .env expostos.

- **internal/utils:**  
  Funções utilitárias para:
  - Manipulação de arquivos e diretórios.
  - Requisições HTTP (client customizado com timeout e configuração de TLS).
  - Extração e comparação de versões.
  - Output formatado (mensagens coloridas no terminal).
  - Leitura dinâmica do arquivo YAML (`dynamic_finders.yml`).

- **pkg/update:**  
  Responsável por atualizar ou verificar a base de dados de vulnerabilidades.

- **database:**  
  Diretório contendo os arquivos de dados e configurações (por exemplo, o arquivo YAML dinâmico).

---

## Configuração Dinâmica via YAML

O arquivo `./database/dynamic_finders.yml` permite definir parâmetros específicos para cada plugin, tema ou outra verificação. Por exemplo, para definir o caminho do arquivo README de um plugin, use:

```yaml
plugins:
  123formular-fur-wp:
    Readme:
      path: README.txt
```

Caso a entrada para o plugin não seja encontrada ou o campo não esteja definido, o scanner utilizará o valor padrão `readme.txt`.

---

## Customização

- **Limite de Concorrência:**  
  O número de goroutines simultâneas pode ser ajustado modificando a constante `concurrencyLimit` em `internal/scanner/scanner.go`.

- **Output Formatado:**  
  As cores e estilos de saída podem ser customizados no pacote de utils responsável pelo output.

- **Atualização dos Dados:**  
  Os arquivos em `./database` (como `plugins.txt`, `themes.txt` etc.) podem ser editados para atualizar as vulnerabilidades conhecidas.

---

## Contribuição

Contribuições são bem-vindas! Se você deseja melhorar o projeto ou adicionar novos recursos, sinta-se à vontade para:

- Abrir issues para relatar bugs ou sugerir melhorias.
- Enviar pull requests com novas funcionalidades ou correções.
- Atualizar a documentação e adicionar testes.

---

## Licença

Distribuído sob a [MIT License](LICENSE). Veja o arquivo LICENSE para mais detalhes.

---

## Créditos

Desenvolvido por [@rafaelwdornelas](https://github.com/rafaelwdornelas)  
Contribuições e feedback são muito bem-vindos!

