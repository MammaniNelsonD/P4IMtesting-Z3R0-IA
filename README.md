# 🚀 P4IMTESTING Z3R0 IA

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Licencia](https://img.shields.io/badge/Licencia-MIT-yellow.svg)](LICENSE)
[![Modo](https://img.shields.io/badge/modo-offline--local-red)]()
[![IA](https://img.shields.io/badge/IA-no-blueviolet)]()
[![Enfoque](https://img.shields.io/badge/enfoque-OSCP%20%2F%20CTF-orange)]()
[![Plataforma](https://img.shields.io/badge/plataforma-Linux%20%2F%20Kali-1f425f.svg?logo=linux&logoColor=white)]()

> 🧠 **Asistente local de metodología para OSCP y CTF.** Pega salidas crudas de tus herramientas de Kali y la herramienta extrae datos, detecta vectores, explica el porqué, propone pasos y te devuelve comandos `one-line` listos para pegar con tu IP, tu IP de Kali y tu dominio ya sustituidos.
>
> ⚠️ **Sin IA. Sin red. Sin OSINT automático.** Todo funciona con reglas y conocimiento embebido, dentro de un laboratorio autorizado.

<p align="center">
  <img alt="Banner P4IMTESTING Z3R0 IA" src="https://img.shields.io/badge/P4IMTESTING-Z3R0--IA-black?style=for-the-badge">
</p>

```
████  █  █  ███ █   █ █████ █████  ████ █████ ███ █   █  ███       █████ ████  ████   ███       ███  ███
█░░░█ █░ █░  █░░██ ██░ ░█░░░█░░░░░█ ░░░░ ░█░░░ █░░██  █░█ ░░░       ░░█░░ ░░░█ █░░░█ █ ░░█       █░░█ ░░█
████░░█████░ █░░█░█ █░░ █░░░████░░░███░░░ █░░░░█░░█░█ █░█░ ██░████   █░░░░███░░████░░█░ ░█░████  █░░█████░
█░░░░ ░░░█░░ █░░█░░░█░░ █░░ █░░░░   ░░█   █░░  █░░█░░██░█░░ █░ ░░░░ █ ░ ░  ░░█ █░░█░ █░░ █░░░░░░ █░░█░░░█░░
█░░░░░  ░█░░███░█░░ █░░ █░░ █████░████░░  █░░ ███░█░░ █░░███ ░░ ░░░█████ ████░░█░░░█░ ███ ░░ ░░░███░█░░░█░░
 ░░       ░░ ░░░ ░░  ░░  ░░  ░░░░░ ░░░░ ░  ░░  ░░░ ░░  ░░ ░░░ ░     ░░░░░ ░░░░ ░░░  ░  ░░░ ░     ░░░ ░░  ░░
  ░        ░  ░░░ ░   ░   ░   ░░░░░ ░░░░    ░   ░░░ ░   ░  ░░░       ░░░░░ ░░░░  ░   ░  ░░░       ░░░ ░   ░
```

---

## 📑 Tabla de contenidos

- [✨ Características](#-características)
- [🛠️ Requisitos e instalación](#️-requisitos-e-instalación)
- [🚀 Uso rápido](#-uso-rápido)
- [🧭 Menú principal](#-menú-principal)
- [🧠 Modo análisis automático](#-modo-análisis-automático)
- [✅ Checklist persistente](#-checklist-persistente)
- [⌨️ Comandos y bash one-liners](#️-comandos-y-bash-one-liners)
- [📚 Metodologías incluidas](#-metodologías-incluidas)
- [🔐 Seguridad y alcance](#-seguridad-y-alcance)
- [📦 Paquete portable](#-paquete-portable)
- [📄 Licencia](#-licencia)

---

## ✨ Características

| 🧩 Característica | 💡 Qué hace |
|---|---|
| 🧠 **Motor de decisión local** | Detecta ~133 firmas de herramientas Kali y aplica 42 reglas para priorizar vectores. |
| 📥 **Entrada cruda masiva** | Pega `nmap`, `ffuf`, `nxc`, `ldapsearch`, `smbclient`, `linpeas`, `winpeas`, `ip a`, etc. juntos. |
| 🎯 **Datos ya sustituidos** | IP objetivo, IP Kali, dominio, usuario, hash y puerto se inyectan en cada comando. |
| 🧭 **Top 10 metodologías** | OSCP end-to-end, Mike's Methodology, HackTricks, PTES, NIST, OWASP WSTG, OSSTMM, MITRE ATT&CK, ISSAF/CEH y workflow OffSec. |
| ✅ **Checklist de 183 items** | 12 fases (P0-P11), progreso por fase, auto-check por evidencia y persistencia en JSON. |
| 🧹 **Bash one-liners** | Limpieza y filtrado de salidas: ANSI, IPs, URLs, correos, puertos, rutas y usuarios LDAP. |
| ⚖️ **Reglas OSCP integradas** | Recordatorios de alcance, Meterpreter en una sola máquina y evidencia obligatoria. |
| 🎨 **CLI con color** | Banner ASCII, secciones contrastadas, barras de progreso y salidas legibles. |
| 🕶️ **Offline y sin secretos** | No llama a ningún servicio externo ni almacena credenciales en el repositorio. |

---

## 🛠️ Requisitos e instalación

Solo necesitas **Python 3.8+** en Kali Linux. No hay dependencias de terceros.

```bash
git clone https://github.com/MammaniNelsonD/P4IMtesting-Z3R0-IA.git
cd P4IMtesting-Z3R0-IA
chmod +x P4IMtesting-Z3R0-IA.py
python3 P4IMtesting-Z3R0-IA.py
```

> 💡 Si descargaste el ZIP portable, descomprímelo y ejecuta el mismo comando desde la carpeta extraída.

---

## 🚀 Uso rápido

```bash
# Menú interactivo
python3 P4IMtesting-Z3R0-IA.py

# Sin colores (útil para logs o pipes)
python3 P4IMtesting-Z3R0-IA.py --no-color

# Precargar objetivo, Kali y dominio
python3 P4IMtesting-Z3R0-IA.py --target 192.168.225.187 --kali 192.168.45.231 --domain access.offsec

# Analizar un fichero directamente
python3 P4IMtesting-Z3R0-IA.py --file salida_nmap.txt --target 192.168.225.187

# Ver solo la biblioteca de metodologías
python3 P4IMtesting-Z3R0-IA.py --methods

# Sesión de máquina concreta
python3 P4IMtesting-Z3R0-IA.py --session "ACCESO-AD"
```

---

## 🧭 Menú principal

| Opción | Función |
|---|---|
| `1` ⚙️ | Configurar objetivo, IP Kali, dominio y credenciales |
| `2` 🧠 | **Modo análisis automático** (pegar salidas en bruto) |
| `3` ✅ | Checklist de la máquina + barra de progreso |
| `4` 📚 | Biblioteca de las TOP 10 metodologías |
| `5` ⌨️ | Generador de comandos por puerto/servicio |
| `6` 🧹 | Utilidades: limpieza, filtros, shells y wordlists |
| `7` 🔑 | Tabla de credenciales y notas |
| `8` 📜 | Historial de análisis de la sesión |
| `9` 📄 | Exportar reporte Markdown |
| `10` 🔄 | Cambiar o crear máquina CTF |
| `11` ⚖️ | Reglas OSCP y recordatorios |
| `0` 🚪 | Salir |

---

## 🧠 Modo análisis automático

1. Entra en la opción `2` y pega toda la salida que quieras, de una o varias herramientas.
2. Termina con una línea que contenga solo `EOF` (también `END` o `FIN`) o pulsa `Ctrl+D`.
3. También puedes cargar un archivo escribiendo `@ruta/al/archivo.txt`.

La herramienta devuelve:

- 🔍 **Datos extraídos**: SO, host, puertos, servicios, versiones, rutas web, IPs, credenciales y hashes.
- 🧨 **Vectores priorizados** con severidad, por qué funcionan y qué haría a continuación.
- 🧾 **Comandos one-line** ya rellenos con tu IP, tu Kali y tu dominio.
- 🧹 **Bash one-liners** para limpiar o filtrar la salida original.
- 🏁 **Conclusión y prioridad**, ordenada por impacto.
- ✅ **Auto-check** de los items del checklist que tienen evidencia suficiente.

Ejemplo de entrada:

```text
53/tcp    open  domain        syn-ack ttl 125 Simple DNS Plus
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: access.offsec)
445/tcp   open  microsoft-ds  Microsoft Windows 7 Professional 7601 Service Pack 1
EOF
```

---

## ✅ Checklist persistente

Cada máquina CTF tiene su propia sesión:

- 📁 Se guarda en `~/.oscp-advisor/sessions/<slug>.json`.
- 📌 El puntero a la sesión activa vive en `~/.oscp-advisor/current.json`.
- 📊 La barra de progreso se calcula por fase y global.
- 🤖 El auto-check solo marca items cuando hay evidencia real, no por simple mención de una herramienta.
- ✍️ Puedes marcar, desmarcar, buscar texto y reiniciar fases desde la opción `3`.

> 🔎 El progreso sobrevive a reinicios de terminal: puedes cerrar la tool y seguir otro día exactamente donde lo dejaste.

---

## ⌨️ Comandos y bash one-liners

Todos los comandos se imprimen en **una sola línea**, sin saltos, con los valores ya resueltos:

```bash
nxc smb 192.168.225.187 -u '' -p ''; nxc smb 192.168.225.187 -u guest -p ''
smbclient -L //192.168.225.187/ -N
nmap --script 'smb-vuln*' -p445 192.168.225.187
ldapsearch -x -H ldap://192.168.225.187 -D '' -w '' -b 'DC=access,DC=offsec' '(objectClass=person)' sAMAccountName
```

Filtros útiles incluidos:

```bash
grep -E '^[0-9]+/(tcp|udp).*open' salida.txt | awk '{print $1}' | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//'
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' salida.txt | sort -uV
grep -iE '^cn:|^sAMAccountName:|^uid:' salida.txt | cut -d' ' -f2 | sort -u
sed -r 's/\x1B\[[0-9;]*[mK]//g' salida.txt > limpio.txt
```

---

## 📚 Metodologías incluidas

| # | Metodología | Enfoque |
|---|---|---|
| 1️⃣ | OSCP End-to-End (Heretek 2026 + Zhaoyi-Fan) | 10 fases, command-first, diseñada para examen PEN-200 |
| 2️⃣ | Mike's OSCP Methodology | 3 vectores cíclicos: enumerar → escalar → re-enumerar |
| 3️⃣ | HackTricks | Checklists por superficie, técnicas y bypasses |
| 4️⃣ | PTES | 7 fases, estándar de proceso para todo el engagement |
| 5️⃣ | NIST SP 800-115 | Planning, Discovery, Attack y Reporting |
| 6️⃣ | OWASP WSTG v4.2 | Testing de aplicaciones web y APIs |
| 7️⃣ | OSSTMM 3 (ISECOM) | 5 canales: físico, humano, telecom, wireless y redes |
| 8️⃣ | MITRE ATT&CK v20 | 15 tácticas Enterprise, complemento de PTES |
| 9️⃣ | ISSAF / EC-Council CEH | Framework académico: management, assessment y reporte |
| 🔟 | Workflow de examen OffSec | AD primero, 3 standalones, gestión del tiempo y reporte continuo |

---

## 🔐 Seguridad y alcance

- ✅ Úsalo **únicamente** en laboratorios, CTFs o sistemas con autorización explícita.
- 🚫 No realiza escaneos, explotación ni conexiones por su cuenta: solo analiza lo que tú pegas.
- 🔑 No guarda contraseñas ni tokens en el repositorio.
- 📝 El directorio `~/.oscp-advisor/` es local a tu usuario y no se versiona.
- ⚖️ La opción `11` muestra los recordatorios OSCP: Meterpreter en una sola máquina, sqlmap prohibido y evidencia obligatoria.

---

## 📦 Paquete portable

El repositorio incluye además `P4IMtesting-Z3R0-IA.zip` con todo el proyecto listo para llevar a otra máquina:

```bash
unzip P4IMtesting-Z3R0-IA.zip -d P4IMtesting-Z3R0-IA
cd P4IMtesting-Z3R0-IA
python3 P4IMtesting-Z3R0-IA.py
```

> 🧳 No incluye el historial de Git ni sesiones personales: solo código, documentación y licencia.

---

## 📄 Licencia

Distribuido bajo licencia [MIT](LICENSE).

## 👤 Autor

**MammaniNelsonD** · [github.com/MammaniNelsonD](https://github.com/MammaniNelsonD) · gosthrecond50@hotmail.com

---

🧠 **P4IMTESTING Z3R0 IA** — *metodiedad antes que velocidad: enumera, documenta, repite.*
