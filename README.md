# WEG Radar — Domain impersonation monitoring (gratuito)

Monitorização de domínios externos semelhantes à marca WEG, sem APIs pagas.

## Novidades
- Descoberta via Certificate Transparency (crt.sh), incluindo pesquisas para variantes como `weg-connect`.
- Ficheiro `data/known_domains.txt` para acrescentar nomes a verificar em cada execução, por exemplo `weg-connect.kz`.
- Verificação de resolução DNS para IPs públicos e resposta HTTP/HTTPS, sem descarregar o corpo das páginas.
- Dashboard apresenta por defeito apenas domínios com resposta HTTP 2xx ("Ativos").
- Um filtro permite consultar "Redireciona", "Acesso restrito" e "Inacessível".
- Histórico dos candidatos para voltar a verificar domínios na recolha seguinte.

## Deploy
GitHub Pages: https://pmram.github.io/weg-external-radar./

GitHub Actions executa a pesquisa diariamente às 07:13 UTC; também podes usar Run workflow.

## Segurança e limites
- "Ativo" significa **resposta HTTP 2xx no momento da verificação**, não que seja um site funcional, legítimo, fraudulento ou que se faça passar pela WEG.
- Redirecionamentos não são seguidos; aparecem numa categoria distinta.
- O scanner restringe as ligações a IPs públicos, aplica timeout e limita paralelismo e número de candidatos.
- Sites geograficamente restritos, protegidos por bot protection ou que exijam autenticação podem não aparecer entre os ativos.
- Os resultados de Certificate Transparency são incompletos e o crt.sh pode falhar temporariamente.
- `weg.net` e subdomínios são excluídos; outros domínios oficiais exigem uma lista verificada em `TRUSTED_DOMAINS`.
- Para identificar verdadeiras páginas de impersonação ainda será necessário inspeção segura do conteúdo e validação humana.

## Adicionar candidatos
Acrescenta uma linha em `data/known_domains.txt` por domínio. Cada alteração inicia nova recolha. São **indícios a verificar**, nunca acusações de fraude.
