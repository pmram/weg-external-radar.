# WEG Radar — Monitorização mundial de possíveis domínios de impersonação

Ferramenta OSINT gratuita para **descobrir domínios** que possam aparentar ser da WEG. A identificação não equivale a fraude confirmada.

## Descoberta mundial, sem APIs pagas

- Certificate Transparency via **crt.sh**: combina pesquisas amplas por `weg-%`, `wegsolut%`, `weg-solut%`, `weg-connect%` e outras variantes em rotação.
- **urlscan.io**: consulta apenas análises **públicas já existentes**, com quota gratuita/sem autenticação, se disponível. Não cria análises públicas nem envia URLs.
- **Sementes confirmadas pelo operador**: `data/known_domains.txt` com `weg-solutions.kz` e `weg-products.ru`. São objetos de investigação, não domínios declarados falsos.
- **Histórico**: retém domínios descobertos nos ciclos anteriores.
- Todas as extensões e países são elegíveis; não há filtro geográfico.
- Validação técnica DNS + HTTP/HTTPS (IP público, sem seguir redirecionamentos, com limite de simultaneidade).
- Até 140 verificações HTTP por execução, com lote em rotação e prioridades para as sementes. Os restantes mantêm-se em "Não verificado".
- Sem chave Brave, sem pagamentos de API. Sujeito a disponibilidade, quotas, limites de GitHub e fontes públicas.

## Porque weg-solutions.kz não aparecia?

O CT anterior usava poucos padrões, entre eles `weg-connect%` (domínio indicado inicialmente), mas não procurava `weg-solut%` ou `weg-%`. Limitava ainda a validação aos primeiros 65 candidatos. A ausência de um nome na pesquisa não demonstra ausência de fraude. A página `weg-products.ru` remete publicamente para `weg-solutions.kz`; a autorização formal dessa relação comercial continua por verificar.

## Configuração

- GitHub Pages: https://pmram.github.io/weg-external-radar./
- Github Actions: **Scan public web**, agendado às 07:13 UTC ou manual.
- `TRUSTED_DOMAINS`: variável opcional, domínios confirmados como oficiais, separados por vírgulas.
- A publicação do GitHub Pages ocorre quando um scan termina com sucesso, lendo a versão mais recente de main.

## Interpretação

- **Ativo:** resposta HTTP 2xx; não demonstra que a página corresponde à marca.
- **Redireciona:** HTTP 3xx não seguido, destino não verificado.
- **Acesso restrito:** HTTP 401/403.
- **Inacessível:** ligação ou DNS falhou a partir do runner.
- **Não verificado:** fora do lote do dia.
- Os sinais e score são triagem de risco de nome, não prova de fraude.
- A ausência de um candidato não constitui prova de segurança, já que fontes públicas não são exaustivas.

## Próximo nível, se necessário

Para detetar efetiva falsificação visual, seria necessário comparar conteúdo e aparência em ambiente de análise isolado, confirmar titularidade e diferenciar distribuidores autorizados. O projeto atual **não** executa conteúdo das páginas nem recolhe credenciais.
