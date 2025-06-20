# .github/scripts/setup-security.sh
#!/bin/bash

echo "🔒 Configurando seguridad del repositorio..."

# Crear archivo .gitleaks.toml
cat > .gitleaks.toml << 'EOF'
title = "Gitleaks Config"
[[rules]]
description = "AWS Access Key"
regex = '''(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'''
tags = ["key", "AWS"]

[[rules]]
description = "AWS Secret Key"
regex = '''(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]'''
tags = ["key", "AWS"]

[[rules]]
description = "GitHub Token"
regex = '''ghp_[0-9a-zA-Z]{36}'''
tags = ["key", "Github"]

[[rules]]
description = "Generic API Key"
regex = '''(?i)((api[_\-\s]?key|apikey)[_\-\s]?[=:]\s?['\"][0-9a-zA-Z]{32,}['\"])'''
tags = ["key", "API"]

[[rules]]
description = "Private Key"
regex = '''-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----'''
tags = ["key", "Private Key"]

[allowlist]
description = "Allowlisted files"
files = ['''^\.?gitleaks.toml$''', '''(.*?)(jpg|gif|png|doc|pdf|bin)$''']
EOF

# Crear archivo .trivyignore
cat > .trivyignore << 'EOF'
# Ignorar vulnerabilidades específicas conocidas y aceptadas
# CVE-2021-12345
EOF

# Crear configuración de Semgrep
mkdir -p .semgrep
cat > .semgrep/config.yml << 'EOF'
rules:
  - id: hardcoded-secret
    pattern-either:
      - pattern: $KEY = "..."
      - pattern: $KEY = '...'
    metavariable-regex:
      metavariable: $KEY
      regex: (?i)(password|passwd|pwd|token|api_key|apikey|secret)
    message: Posible secreto hardcodeado
    severity: ERROR
    languages: [python, javascript, java, go]
EOF

echo "✅ Archivos de configuración creados"
EOF

chmod +x .github/scripts/setup-security.sh
