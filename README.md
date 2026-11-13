# WEG Radar — Brand Impersonation Watch

Monitorização **gratuita**, passiva e preliminar de domínios que possam imitar a WEG. Não pesquisa notícias.

## Fontes e custos
- **crt.sh** — consultas públicas aos registos de Certificate Transparency (CT); não necessita de chave de API.
- **GitHub Actions + GitHub Pages** — recolha diária e publicação estática, sujeitos aos limites do plano GitHub e à disponibilidade do serviço.
- **Não necessita de Brave, subscrições ou APIs pagas.**

## Como funciona
1. Consulta registos públicos de certificados emitidos para nomes que contenham `weg`.
2. Exclui `weg.net`, os seus subdomínios e outros domínios expressamente confiáveis.
3. Filtra nomes de notícias, redes sociais e outros sites irrelevantes.
4. Classifica candidatos segundo semelhança do nome do domínio. A prioridade máxima nesta modalidade é **Média**.
5. Apresenta o domínio e sinais de triagem no dashboard. Os URLs são **inferidos** a partir dos nomes encontrados nos certificados e **não foram visitados/confirmados**.

**Um certificado não prova que o site esteja ativo ou seja fraudulento.** Pode tratar-se de um distribuidor legítimo, um certificado antigo ou um nome não utilizado. É obrigatória validação humana antes de qualquer ação.

## Configuração
1. Confirmar **Settings → Pages → Source: GitHub Actions**.
2. Abrir **Actions → Scan public web → Run workflow** para uma pesquisa manual.
3. A execução automática ocorre diariamente às 07:13 UTC.
4. Abrir https://pmram.github.io/weg-external-radar./
5. Opcional: em **Settings → Secrets and variables → Actions → Variables** criar `TRUSTED_DOMAINS` com lista de domínios oficiais verificados, separados por vírgulas.

Não é necessário criar nem configurar `BRAVE_SEARCH_API_KEY`.

## Limitações
- CT cobre nomes que apareceram em certificados públicos, não a totalidade da Internet.
- O serviço crt.sh pode estar temporariamente lento, indisponível ou limitar respostas grandes.
- Esta versão não confirma conteúdo, formulários, aparência gráfica, resolução DNS, atividade do site, proprietário ou intenção maliciosa.
- A triagem não deteta toda a variedade de typosquatting.
- A recolha é executada nas Actions, não no browser do visitante.
