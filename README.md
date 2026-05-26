<div align="center">

```
██████╗  ██████╗ ███╗   ███╗██╗███╗   ██╗██╗
██╔══██╗██╔═══██╗████╗ ████║██║████╗  ██║██║
██║  ██║██║   ██║██╔████╔██║██║██╔██╗ ██║██║
██║  ██║██║   ██║██║╚██╔╝██║██║██║╚██╗██║██║
██████╔╝╚██████╔╝██║ ╚═╝ ██║██║██║ ╚████║██║
╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝
```

**Suite OSINT de reconocimiento ofensivo para dominios y empresas**

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)]()
[![HTTPS](https://img.shields.io/badge/HTTPS-Enabled-blue?style=flat-square&logo=letsencrypt&logoColor=white)]()

*Desarrollado como proyecto de fin de módulo — Máster en Ciberseguridad*

</div>

---

## ¿Qué es DOMINI?

DOMINI es una plataforma OSINT web que integra dos herramientas de reconocimiento propias — **DOMINUS** (análisis de dominios) y **SENTINEL** (análisis de IPs) — en un único panel con autenticación, historial de escaneos, motor de correlación de señales y exportación de informes.

Diseñada para pentesters, analistas de seguridad y estudiantes de ciberseguridad que necesitan una herramienta funcional, rápida y con resultados accionables.

---

## Arquitectura de la suite

```
DOMINI (panel web Flask)
├── DOMINUS — Reconocimiento de dominios
│   ├── WHOIS            → registrador, fechas, privacidad
│   ├── DNS              → SPF, DMARC, DKIM, registros A/MX/TXT
│   ├── Subdominios      → enumeración pasiva vía Certificate Transparency
│   ├── Puertos          → escaneo TCP con nmap, fingerprinting de versión
│   ├── Cabeceras HTTP   → headers de seguridad, banner del servidor
│   └── LeakRadar        → menciones del dominio en Pastebin
│
├── SENTINEL — Análisis de IPs
│   ├── Geolocalización  → país, ciudad, ISP, ASN
│   ├── Reputación       → AbuseIPDB, OTX AlienVault
│   ├── Cloud            → detección AWS/Azure/GCP/Cloudflare
│   ├── Tor              → verificación de nodos de salida activos
│   └── Puertos          → escaneo independiente con severidad por puerto
│
├── Motor de correlación → señales cruzadas entre DOMINUS y SENTINEL
├── Supply Chain         → dependencias externas y CDNs detectados
├── Shadow IT            → subdominios no declarados
└── Secretos expuestos   → búsqueda en repositorios públicos
```

---

## Funcionalidades principales

### 🔍 Reconocimiento completo de dominio
Lanza un análisis en 6 fases sobre cualquier dominio: WHOIS, DNS, subdominios, puertos, cabeceras HTTP y búsqueda de filtraciones. Genera un **Risk Score 0-100** con desglose por fase y recomendaciones accionables.

### 🛡️ Análisis de IPs con SENTINEL
Para cada IP descubierta, SENTINEL lanza un análisis independiente: geolocalización, reputación en bases de datos de abuso, detección de nodos Tor, identificación de proveedor cloud y escaneo de puertos con severidad.

### 🔗 Motor de correlación de señales
El diferenciador clave de DOMINI: cruza los hallazgos de DOMINUS y SENTINEL para generar **insights de alta confianza** que ninguna herramienta detectaría por separado.

| Regla | Condición | Severidad |
|-------|-----------|-----------|
| Puerto confirmado | Puerto de alto riesgo detectado por ambas herramientas | HIGH |
| Email sin protección | DMARC p=none con servidor MX activo | HIGH |
| Servidor sin hardening | ≥5 cabeceras de seguridad ausentes | HIGH |
| Hosting compartido expuesto | Servicios sensibles en IONOS/OVH/Arsys | MEDIUM |
| Superficie de ataque amplia | >3 puertos confirmados por ambas herramientas | MEDIUM |
| Stack tecnológico visible | Banner expuesto + dependencias externas | MEDIUM |

### 📊 Panel web con historial
- Dashboard con KPIs: targets monitorizados, scans completados, score medio, alertas activas
- Historial de escaneos por target con gráfica de evolución del Risk Score
- Tendencia entre scans (↑ riesgo aumentó / ↓ riesgo bajó / = sin cambios)

### 🚨 Alertas comparativas automáticas
Cada nuevo scan compara con el anterior del mismo target y genera alertas si:
- El Risk Score subió ≥5 puntos
- Aparece un puerto de alto riesgo nuevo
- DMARC se debilita o desaparece
- SPF es eliminado
- Los subdominios aumentan significativamente

### 🌐 Supply Chain Fingerprinting
Detecta dependencias externas cargadas por el dominio objetivo: CDNs, librerías JS, trackers, proveedores de analytics y dominios de terceros vía dns-prefetch.

### 🔒 Seguridad de la plataforma
- Autenticación con Flask-Login + bcrypt
- Registro público con validación estricta
- Recuperación de contraseña por email con tokens SHA256 (expiración 1h)
- Protección contra fuerza bruta: bloqueo de cuenta tras 5 intentos fallidos (15 min)
- Rate limiting por IP
- CSRF en todos los formularios
- Headers de seguridad: HSTS, X-Frame-Options, CSP, X-Content-Type-Options
- Cookies: Secure, HttpOnly, SameSite=Lax
- HTTPS con certificado propio

### 🌍 Internacionalización
Interfaz completa en **Español**, **Inglés** y **Ruso** con traducción dinámica de todos los hallazgos y mensajes del sistema.

### 📄 Exportación de informes
Exporta informes completos en HTML standalone con todos los hallazgos, correlaciones, datos raw por fase y JSON embebido. Listos para adjuntar a un informe de auditoría.

---

## Stack técnico

| Componente | Tecnología |
|------------|------------|
| Backend | Python 3.9+, Flask 3.0 |
| Base de datos | SQLite (dev) / PostgreSQL (prod) |
| Auth | Flask-Login, Flask-Bcrypt |
| Reconocimiento | nmap, python-whois, dnspython, requests |
| Frontend | HTML5, CSS3, JS vanilla |
| HTTPS | pyOpenSSL |
| Despliegue | Railway / cualquier VPS con Python |

---

## Instalación

```bash
# 1. Clona los tres repositorios
git clone https://github.com/KristinaSabitova/domini.git
git clone https://github.com/KristinaSabitova/dominus.git
git clone https://github.com/KristinaSabitova/sentinel.git

# 2. Configura DOMINI
cd domini
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Configura las variables de entorno
cp .env.example .env
# Edita .env con tus valores

# 4. Genera certificados SSL (desarrollo)
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/domini.key \
  -out certs/domini.crt -days 365 -nodes -subj "/CN=localhost"

# 5. Arranca
python app.py
# → https://localhost:8443
```

---

## Variables de entorno

```bash
SECRET_KEY=               # Clave secreta Flask (obligatoria en producción)
DATABASE_URL=             # URL de BD (por defecto SQLite local)
ADMIN_USERNAME=           # Usuario administrador inicial
ADMIN_PASSWORD=           # Contraseña administrador inicial
DOMINUS_DIR=              # Ruta al repositorio dominus
SENTINEL_DIR=             # Ruta al repositorio sentinel
DEFAULT_LANG=es           # Idioma por defecto (es/en/ru)

# Opcional — para recuperación de contraseña por email
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=
MAIL_PASSWORD=
MAIL_FROM=
```

---

## Casos de uso

- **Auditorías de seguridad**: análisis rápido de la superficie de ataque de un dominio antes de un pentest
- **Monitorización continua**: re-escanea periódicamente y recibe alertas de cambios
- **CTF / laboratorios**: reconocimiento pasivo de objetivos en entornos de práctica
- **Due diligence**: evaluación del nivel de seguridad de un proveedor o empresa
- **Formación**: herramienta didáctica para aprender OSINT y reconocimiento ofensivo

---

## Repositorios relacionados

| Repositorio | Descripción |
|-------------|-------------|
| [KristinaSabitova/dominus](https://github.com/KristinaSabitova/dominus) | Motor de reconocimiento de dominios (CLI) |
| [KristinaSabitova/sentinel](https://github.com/KristinaSabitova/sentinel) | Motor de análisis de IPs (CLI) |
| [KristinaSabitova/domini](https://github.com/KristinaSabitova/domini) | Suite web que integra ambos |

---

## Roadmap

- [ ] Integración con AbuseIPDB y OTX (API keys configurables desde el panel)
- [ ] Escaneos programados / alertas por email
- [ ] Soporte PostgreSQL para despliegue en producción
- [ ] API REST para integración con otras herramientas
- [ ] Módulo de comparación entre dos dominios

---

<div align="center">

**DOMINI** · OSINT Suite · v0.1.0

*Desarrollado por [Kristina Sabitova](https://github.com/KristinaSabitova)*

</div>
