# Segurança do Aeternitas

O acesso e os downloads protegidos funcionam somente quando o site é servido por server.js. Não publique esta pasta em uma hospedagem estática, pois ela exporia os executáveis sem a verificação de sessão.

Antes de iniciar, defina uma senha longa e exclusiva nas variáveis AETERNITAS_USER e AETERNITAS_PASSWORD. Elas não ficam no código enviado ao navegador.

Para disponibilizar publicamente, use HTTPS em uma hospedagem que execute Node.js. Mantenha o Node atualizado, limite o acesso administrativo ao servidor e faça cópias de segurança do projeto.

Os controles incluídos são: cookie HttpOnly e SameSite, expiração de sessão, limitação de tentativas de login, comparação segura de senha, proteção contra páginas incorporadas e cabeçalhos para reduzir ataques comuns no navegador.
