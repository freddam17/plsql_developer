# SECURITY.md
# 🔒 Política de Seguridad

## 🛡️ Versiones Soportadas

| Versión | Soportada          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## 🚨 Reportar una Vulnerabilidad

Si descubres una vulnerabilidad de seguridad, por favor:

1. **NO** la reportes públicamente en un issue
2. Envía un email a: security@tudominio.com
3. Incluye:
   - Descripción detallada de la vulnerabilidad
   - Pasos para reproducirla
   - Impacto potencial
   - Posible solución (si la tienes)

## 🔍 Proceso de Seguridad

Este repositorio utiliza las siguientes herramientas de seguridad:

### Escaneos Automáticos
- **Secretos:** GitLeaks, TruffleHog
- **Dependencias:** OWASP Dependency Check, Snyk
- **Código:** CodeQL, Semgrep
- **Contenedores:** Trivy, Hadolint
- **IaC:** Checkov

### Frecuencia de Escaneos
- En cada Push/PR
- Diariamente a las 2:00 AM UTC
- Manualmente cuando sea necesario

## 📊 Métricas de Seguridad

Los reportes de seguridad se generan automáticamente y están disponibles en:
- Actions → Security Scan → Artifacts
- Security Tab (para vulnerabilidades de dependencias)

## 🏃 Ejecutar Escaneo Manual

Para ejecutar un escaneo de seguridad manualmente:

1. Ve a Actions → Security Scan Complete
2. Click en "Run workflow"
3. Selecciona el tipo de escaneo:
   - `full`: Todos los escaneos
   - `quick`: Solo escaneos rápidos
   - `dependencies-only`: Solo dependencias
   - `secrets-only`: Solo secretos
   - `code-only`: Solo análisis de código

## 📝 Checklist de Seguridad para PRs

- [ ] No incluye secretos o credenciales
- [ ] Las dependencias están actualizadas
- [ ] El código no tiene vulnerabilidades conocidas
- [ ] Los tests de seguridad pasan
- [ ] La documentación está actualizada
