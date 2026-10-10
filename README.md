# hack_cameraWeb


# Estructura para comprender el proyecto a realizar 

Este repositorio conserva dos objetivos de servir como material educativo y mantener las herramientas de laboratorio `ft_malcolm`, reconocimiento de cámaras y redes, escenarios ARP y el canal TLS.

Por cierto, el proyecto fue estudiado y desarrollado durante septiembre de 2026 por lo que debido al ritmo constante de mejoras y actualizaciones, es probable que algunas partes queden obsoletas en un futuro no muy lejano.

## Recorrido

| Etapa | Aprenderás | Resultado esperado |
|---|---|---|
| **01 · Linux** | Usuarios, permisos, paquetes, procesos, SSH y firewall. | Administrar una VM y explicar qué privilegios tiene cada proceso. |
| **02 · Redes** | OSI, Ethernet, ARP, IP, rutas, puertos y protocolos. | Seguir el recorrido de una conexión cliente-servidor. |
| **03 · Pentesting** | Alcance, reconocimiento, enumeración, análisis y reporte. | Evaluar un objetivo de laboratorio sin salirte del alcance. |
| **04 · Hack The Box** | Preparar una VM, conectar la VPN y documentar una práctica. | Resolver ejercicios respetando las reglas de la plataforma. |

### Cómo aprovechar estos apuntes

1. Lee el concepto antes de copiar un comando.
2. Prueba primero en una VM desechable o en loopback.
3. Anota el comando, el resultado esperado y lo que observaste.
4. Restaura la VM al terminar y guarda solo evidencias no sensibles.

---

## 01 · Linux

### Usuarios y permisos

Linux es multiusuario: cada cuenta y proceso opera con permisos concretos. `root` puede administrar el sistema; trabaja con una cuenta normal y utiliza `sudo` solo cuando haga falta. Esto reduce el impacto de errores y software comprometido.

| Comando | Para qué sirve |
|---|---|
| `whoami` | Ver la cuenta actual. |
| `id` | Consultar UID, GID y grupos. |
| `sudo comando` | Ejecutar una operación con privilegios administrativos. |
| `sudo -i` | Abrir una sesión administrativa; `exit` la cierra. |
| `adduser nombre` | Crear una cuenta en sistemas que incluyen esta utilidad. |
| `passwd nombre` | Cambiar la contraseña de una cuenta. |
| `ls -l` | Ver propietarios y permisos de archivos. |
| `chown usuario:grupo ruta` | Cambiar propietario y grupo. |
| `chmod modo ruta` | Cambiar permisos de lectura, escritura y ejecución. |

Los permisos se aplican al propietario, al grupo y a los demás usuarios. `chmod 600 archivo` permite que solo el propietario lo lea y escriba. Evita `chmod 777`: suele conceder más acceso del necesario.

### Paquetes y actualizaciones

APT instala paquetes desde los repositorios configurados y resuelve sus dependencias. En terminal interactiva se suele usar `apt`; `apt-get` continúa siendo útil en scripts.

```bash
sudo apt update           # Actualiza el índice de paquetes
apt search nombre         # Busca un paquete
apt show nombre           # Consulta información del paquete
sudo apt install nombre   # Instala el paquete
```

Revisa los cambios propuestos antes de confirmarlos. Para instalar software fuera de los repositorios, verifica su procedencia e instrucciones.

### Procesos y trabajos

| Comando | Qué muestra o hace |
|---|---|
| `w` / `who` | Sesiones de usuario. |
| `ps -ef` | Instantánea de los procesos. |
| `ps -ejH` | Procesos organizados en árbol. |
| `top` | Procesos y uso de recursos en tiempo real. |
| `jobs` | Trabajos de la shell actual. |
| `Ctrl+Z`, `bg`, `fg` | Suspender, reanudar en segundo plano y volver al primer plano. |

Añadir `&` al final de un comando lo inicia en segundo plano dentro de esa shell. `nohup comando >salida.log 2>&1 &` permite que siga al cerrar la terminal. Para servicios persistentes, usa el gestor de servicios del sistema.

En una máquina propia, `sudo systemctl poweroff` apaga el sistema y `sudo systemctl reboot` lo reinicia. Guarda el trabajo antes de hacerlo.

### SSH: acceso remoto cifrado

SSH protege la comunicación y autentica el servidor con una clave de host. El usuario puede autenticarse con contraseña o con claves. Verifica la huella del servidor por un canal confiable en la primera conexión; el cifrado no compensa una contraseña débil ni una clave privada expuesta.

En una VM Debian o Ubuntu:

```bash
sudo apt install openssh-server
sudo systemctl enable --now ssh
systemctl status ssh
```

Desde un equipo autorizado:

```bash
ssh usuario@IP_DE_LA_VM
```

Para crear una clave:

```bash
ssh-keygen -t ed25519
ssh-copy-id usuario@IP_DE_LA_VM
```

Mantén privada la clave secreta. En servidores, limita las cuentas permitidas y el acceso de red al servicio SSH.

### Procesos de red y firewall

En Linux actual, `ip` y `ss` suelen sustituir a las herramientas antiguas `ifconfig` y `netstat`:

```bash
ip addr             # Interfaces y direcciones
ip route            # Tabla de rutas
ss -lntup           # Puertos TCP/UDP en escucha
ss -tan             # Conexiones TCP
```

En macOS puedes consultar interfaces y sockets con `ifconfig`, `netstat -rn` y `lsof -nP -i`. Los nombres de interfaz dependen del equipo.

Un firewall controla conexiones entrantes, salientes y reenviadas. Utiliza la herramienta de tu distribución, como `ufw` o `nftables`. Antes de modificar reglas remotamente, conserva una forma de recuperar el acceso. Define qué tráfico necesitas y permite solo ese tráfico.

---

## 02 · Fundamentos de redes

### Modelo OSI en una mirada

El modelo OSI divide la comunicación en siete capas. Es un marco para razonar sobre protocolos; las redes reales también se describen con el modelo TCP/IP.

| Capa | Idea principal | Ejemplos |
|---|---|---|
| 7 · Aplicación | Protocolos usados por las aplicaciones. | HTTP, DNS, SSH, DHCP. |
| 6 · Presentación | Formato y transformación de datos. | Codificación, serialización, cifrado. |
| 5 · Sesión | Organización de intercambios. | Concepto lógico, a menudo integrado en otras capas. |
| 4 · Transporte | Comunicación entre procesos mediante puertos. | TCP, UDP. |
| 3 · Red | Direccionamiento y encaminamiento. | IPv4, IPv6, ICMP, routers. |
| 2 · Enlace | Entrega dentro del enlace local. | Ethernet, Wi‑Fi, MAC, switches. |
| 1 · Física | Transporte de señales. | Cobre, fibra, radio. |

Al enviar datos, las capas añaden información de control (encapsulación). En recepción, la pila interpreta esa información. Las capas se relacionan lógicamente con sus pares, aunque el procesamiento atraviesa las capas locales.

### LAN, Ethernet y ARP

Una LAN conecta equipos en un segmento local. Ethernet organiza los datos en tramas con direcciones MAC; los switches aprenden qué MAC se encuentra en cada puerto.

ARP permite encontrar la MAC asociada a una dirección IPv4 en el enlace local. No autentica las respuestas, lo que permite estudiar la suplantación ARP como riesgo. Hazlo solo en una red virtual aislada que controles.

Las direcciones privadas pueden repetirse en redes diferentes. Una VM conectada mediante NAT, puente o red interna tendrá un alcance distinto: confirma el modo de red antes de practicar.

### IP, subredes y rutas

Una dirección IP identifica una interfaz dentro de una red. La máscara o el prefijo CIDR determinan qué parte corresponde a la red. Por ejemplo, `/24` equivale a `255.255.255.0`.

```bash
ip route                         # Consultar rutas
ip route get 10.42.0.20          # Ver la ruta hacia un destino del laboratorio
traceroute IP_AUTORIZADA         # Observar saltos, si está instalado
```

Los routers reenvían paquetes según sus tablas de rutas. La ruta por defecto se usa cuando no existe una ruta más específica; cambiarla puede interrumpir la conectividad.

### TCP, UDP y puertos

TCP ofrece un flujo ordenado y fiable. UDP envía datagramas sin garantizar por sí mismo entrega u orden. Los puertos identifican servicios de transporte en un equipo; encontrar uno abierto no demuestra que exista una vulnerabilidad.

```bash
ss -lntup   # Consultar servicios locales en escucha
```

### DHCP, DNS y HTTP

- **DHCP** asigna parámetros de red, como dirección IP, gateway y resolver DNS.
- **DNS** consulta registros asociados a nombres. Las respuestas pueden variar con el resolver o el momento.
- **HTTP** transporta intercambios web. **HTTPS** protege el canal con TLS y permite autenticar el servidor mediante certificados.

Para observar una resolución local sin escanear equipos:

```bash
getent ahostsv4 ejemplo.invalid
```

---

## 03 · Pentesting con alcance definido

Una evaluación empieza por la autorización, no por una herramienta. Define por escrito las máquinas y redes permitidas, el horario, las técnicas excluidas, el manejo de datos y cómo detener y restaurar el ejercicio.

### Método de trabajo

1. **Preparar:** identifica objetivos autorizados y crea snapshots recuperables.
2. **Reconocer:** reúne información solo de los activos incluidos en el alcance.
3. **Descubrir y enumerar:** identifica hosts y servicios del segmento de práctica; registra evidencia y límites.
4. **Analizar:** contrasta versiones y configuraciones con fuentes fiables; considera falsos positivos.
5. **Validar:** demuestra el impacto de forma controlada en una VM preparada, con el mínimo cambio posible.
6. **Cerrar:** detén procesos, restaura el entorno y redacta hallazgos, impacto y mitigaciones.

Los modelos históricos también hablan de acceso, persistencia y borrado de rastros. En formación, estúdialos para reconocer amenazas y mejorar detección y respuesta; no los uses para ocultar actividad o alterar sistemas ajenos.

### Reconocimiento y escaneo en una VM propia

Estos ejemplos son para una subred de laboratorio bajo tu control. Comprueba el rango antes de ejecutarlos:

```bash
# Descubrimiento de hosts en la red virtual aislada de este proyecto
nmap -sn 10.42.0.0/24

# Identificación limitada de servicios de una VM propia
nmap -sV -p 22,80,443,554 IP_DE_TU_VM
```

Evita usar escaneos amplios, detección agresiva o scripts de vulnerabilidades como primera opción: pueden generar tráfico elevado o interactuar con servicios de formas inesperadas. Consulta la documentación de Nmap y limita objetivos y puertos.

La enumeración puede estudiar servicios configurados para el ejercicio, como SMB/NetBIOS, SNMP, NTP, NFS, SMTP, DNS o LDAP. No pruebes contraseñas por defecto ni fuerza bruta en sistemas reales.

### Vulnerabilidades, CVE y Metasploit

Una CVE es un identificador público de una vulnerabilidad. La versión de un servicio por sí sola no confirma que sea vulnerable: también importan los parches, la configuración y las mitigaciones.

Metasploit organiza herramientas en módulos auxiliares, exploits y postexplotación. Para aprender a interpretar un módulo en una máquina deliberadamente vulnerable, consulta primero sus referencias y requisitos:

```text
msfconsole
search <producto-o-CVE>
info <ruta-del-módulo>
```

El repositorio no añade una integración propia con Metasploit. Antes de ejecutar un módulo en cualquier plataforma, revisa sus reglas y comprueba que el objetivo esté autorizado. Usa imágenes vulnerables aisladas y restaurables; no generes ni despliegues malware, payloads o mecanismos de persistencia contra equipos ajenos.

### Captura de tráfico

Wireshark permite inspeccionar tráfico gráficamente; `tcpdump` ofrece una captura desde terminal. Captura solo el tráfico de tu práctica: un archivo de captura puede contener credenciales o datos personales.

```bash
# Loopback de esta máquina
sudo tcpdump -i lo -nn

# En una VM propia, sustituye INTERFAZ e IP por los valores de tu red aislada
sudo tcpdump -i INTERFAZ -nn host IP_DE_TU_VM
```

Guarda capturas con permisos privados, revísalas antes de compartirlas y elimina los datos que ya no necesites.

### Wi‑Fi y MiTM

Los ataques de intermediario ayudan a entender los riesgos de confianza en redes locales. Practica únicamente con un punto de acceso, clientes y máquinas virtuales creados para el ejercicio, desconectados de redes domésticas, empresariales o públicas. Analiza cómo TLS, la validación de certificados y la segmentación reducen el riesgo.

---

## 04 · Hack The Box

Hack The Box proporciona objetivos y reglas de alcance propios. Sigue las reglas actuales y trabaja únicamente con la máquina que te hayan asignado.

1. Selecciona un laboratorio permitido y descarga su perfil VPN.
2. Conéctate desde una VM dedicada, sin rutas innecesarias hacia tu red personal.
3. Toma notas de hipótesis, comandos y resultados; no guardes secretos en el repositorio.
4. Al terminar, detén la VPN y protege o elimina los archivos temporales.

En Debian o Ubuntu, instala OpenVPN si las instrucciones de tu laboratorio lo requieren:

```bash
sudo apt install openvpn
sudo openvpn --config PERFIL_AUTORIZADO.ovpn
```

Las técnicas y herramientas se limitan al alcance concedido por la plataforma.

---

## Laboratorio de este repositorio

El repositorio incluye herramientas C y Python, ejercicios de reconocimiento, escenarios ARP, un canal TLS y una red virtual Docker. `ft_malcolm` es uno de los ejercicios; el resto de la guía se centra en los fundamentos necesarios para entender y practicar seguridad de forma responsable.

### Preparar y probar

Requisitos: compilador C11, `make`, Bash y una versión de Python admitida por `pyproject.toml`. Mantén las dependencias Python en un entorno virtual:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

```bash
make             # Compilar
make test        # Pruebas C, CLI y Python
make debug       # Compilación con sanitizadores, si el compilador los admite
```

Las pruebas automáticas no ejecutan escaneos, envenenamiento ARP ni escenarios de red. Para revisar las opciones disponibles, usa `--help` en las herramientas. Consulta el [manual del laboratorio](docs/MANUAL.md) antes de iniciar escenarios. La configuración Docker requiere Docker Engine y Compose; no se afirma aquí que se haya probado en todos los sistemas.

## Referencias

- [OpenClassrooms: Linux](https://openclassrooms.com/)
- [TryHackMe](https://tryhackme.com/)
- [Hack The Box](https://www.hackthebox.com/)
- [Manual de Nmap](https://nmap.org/book/man.html)
- [RFC 826: ARP](https://datatracker.ietf.org/doc/html/rfc826)
- [Documentación de Metasploit](https://docs.metasploit.com/)
- [Manual del laboratorio](docs/MANUAL.md)

> Estos apuntes son una guía de estudio, no sustituyen la documentación oficial actual de cada sistema, herramienta o plataforma.
