# Apuntes de Linux, redes y ciberseguridad

> Versión traducida, corregida y reorganizada en español.  
> Las prácticas de seguridad deben realizarse únicamente en tus propios equipos, laboratorios autorizados o plataformas como TryHackMe y Hack The Box.

## I. Fundamentos de Linux

### Usuarios y permisos

Linux es un sistema **multiusuario**: varias personas pueden utilizar la misma máquina, incluso al mismo tiempo, por ejemplo mediante conexiones remotas.

- **root** es el superusuario. Tiene control total sobre el sistema y puede ejecutar tareas administrativas.
- Los usuarios normales tienen permisos limitados. Es más seguro trabajar habitualmente con una cuenta sin privilegios, porque un programa malicioso ejecutado con esa cuenta tendrá el mismo alcance limitado que el usuario.
- Los usuarios pueden pertenecer a grupos, que sirven para gestionar permisos compartidos.

| Comando | Función |
|---|---|
| `sudo comando` | Ejecuta un comando temporalmente con privilegios administrativos. |
| `sudo su` | Abre una sesión como root hasta ejecutar `exit`. |
| `sudo adduser nombre_usuario` | Crea un usuario y, normalmente, su directorio personal en `/home/nombre_usuario`. |
| `sudo passwd nombre_usuario` | Cambia la contraseña de un usuario. |
| `ls -l` | Muestra los permisos, propietario y grupo de archivos y directorios. |
| `sudo chown nuevo_propietario archivo` | Cambia el propietario de un archivo. |
| `chmod permisos archivo` | Modifica los permisos de lectura, escritura y ejecución. |

Los permisos se expresan para tres categorías:

- **Usuario propietario**.
- **Grupo propietario**.
- **Otros usuarios**.

Por ejemplo:

```bash
chmod 755 script.sh
```

Significa:

- propietario: lectura, escritura y ejecución;
- grupo: lectura y ejecución;
- otros: lectura y ejecución.

***

### Instalar programas con APT

En distribuciones basadas en Debian, como Ubuntu o Kali Linux, el software se gestiona mediante paquetes.

| Concepto | Explicación |
|---|---|
| Paquete | Archivo que contiene el programa, sus archivos y la información necesaria para instalarlo. En Debian suele tener extensión `.deb`. |
| Repositorio | Servidor o colección de servidores desde donde se descargan los paquetes. |
| Dependencia | Paquete adicional que otro programa necesita para funcionar correctamente. |
| APT | Herramienta de administración de paquetes que resuelve dependencias e instala, actualiza o elimina software. |

Comandos habituales:

```bash
sudo apt update
```

Actualiza la lista local de paquetes disponibles en los repositorios.

```bash
apt search nombre_paquete
```

Busca paquetes por nombre o descripción.

```bash
sudo apt install nombre_paquete
```

Instala un paquete.

```bash
sudo apt remove nombre_paquete
```

Desinstala un paquete, conservando normalmente algunos archivos de configuración.

```bash
sudo apt autoremove
```

Elimina dependencias que ya no utiliza ningún paquete instalado.

Aunque aún se ve `apt-get` en documentación antigua, en uso interactivo moderno suele preferirse `apt`.

***

### Supervisar la actividad del sistema

Linux permite ejecutar muchos procesos y gestionar múltiples usuarios de forma simultánea. Estos comandos ayudan a comprobar qué ocurre en la máquina:

| Comando | Función |
|---|---|
| `w` | Muestra usuarios conectados, carga del sistema y lo que ejecutan. |
| `who` | Lista los usuarios conectados. |
| `ps` | Muestra procesos asociados a la terminal o usuario actual. |
| `ps -ef` | Lista procesos de todos los usuarios. |
| `ps -ejH` | Muestra los procesos en forma de árbol jerárquico. |
| `top` | Monitoriza procesos, CPU, memoria y carga del sistema en tiempo real. |
| `htop` | Alternativa visual e interactiva a `top`, si está instalada. |
| `sudo halt` | Detiene el sistema. |
| `sudo reboot` | Reinicia el sistema. |

En `w` y `top`, el valor de *load average* indica cuántas tareas están ejecutándose o esperando tiempo de CPU. No debe interpretarse aislado: hay que compararlo con el número de núcleos disponibles en el equipo.

***

### Ejecutar procesos en segundo plano

Un proceso en primer plano ocupa la terminal hasta que finaliza. Para poder seguir utilizando la terminal, se puede ejecutarlo en segundo plano.

| Método | Función |
|---|---|
| `comando &` | Inicia un proceso en segundo plano. |
| `nohup comando &` | Evita que el proceso se cierre al terminar la sesión de terminal. |
| `Ctrl + Z` | Suspende temporalmente el proceso en primer plano. |
| `bg` | Reanuda un proceso suspendido en segundo plano. |
| `jobs` | Muestra los trabajos asociados a la terminal actual. |
| `fg` | Devuelve un trabajo al primer plano. |

Ejemplos:

```bash
cp video.avi copia_video.avi &
```

```bash
nohup python3 servidor.py &
```

La salida de `nohup` se redirige normalmente al archivo `nohup.out` si no se especifica otro destino.

***

### Conexión remota segura con SSH

SSH permite acceder de forma remota a otra máquina y administrar servidores mediante una conexión cifrada.

Su seguridad se basa en:

1. **Autenticación del servidor**, para comprobar que te conectas al equipo esperado.
2. Intercambio de claves y negociación de algoritmos.
3. Cifrado simétrico de la sesión una vez acordada una clave compartida.
4. Protección de la integridad de los datos para detectar modificaciones durante la transmisión. [openssh](https://www.openssh.org/manual.html)

Instalación del servidor SSH en sistemas Debian/Ubuntu:

```bash
sudo apt update
sudo apt install openssh-server
sudo systemctl enable --now ssh
```

Comprobar su estado:

```bash
sudo systemctl status ssh
```

Conectarse desde otra máquina:

```bash
ssh usuario@direccion_ip
```

Ejemplo:

```bash
ssh leo@192.168.1.50
```

El puerto predeterminado de SSH es el 22. Si el servidor está detrás de un cortafuegos, ese puerto debe estar permitido solo cuando sea necesario.

#### Autenticación mediante claves

En lugar de utilizar contraseña, es recomendable usar claves pública y privada:

```bash
ssh-keygen
```

Después, se copia la clave pública al servidor:

```bash
ssh-copy-id usuario@direccion_ip
```

La clave privada debe mantenerse siempre secreta. La pública puede instalarse en los servidores a los que quieras acceder.

***

### Analizar conexiones y tráfico de red

Un nombre de dominio, como `google.com`, es más fácil de recordar que una dirección IP. El DNS se encarga de resolver nombres de dominio a direcciones IP.

| Comando | Función |
|---|---|
| `host google.com` | Consulta la resolución DNS de un dominio. |
| `dig google.com` | Realiza consultas DNS más detalladas. |
| `ip addr` | Muestra interfaces y direcciones IP. |
| `ip link` | Muestra interfaces de red. |
| `ip route` | Muestra la tabla de rutas. |
| `ss -tulpn` | Muestra puertos y sockets en escucha. |
| `netstat` | Herramienta antigua para analizar conexiones; hoy suele sustituirse por `ss`. |
| `whois dominio.com` | Consulta datos de registro de un dominio, cuando estén disponibles. |

`ifconfig` y `netstat` todavía aparecen en muchos apuntes, pero en distribuciones Linux actuales suelen considerarse herramientas heredadas. Es preferible utilizar `ip` y `ss`.

Ejemplos:

```bash
ip addr
ip route
ss -tulpn
```

Estados frecuentes de TCP:

- `LISTEN`: un servicio está esperando conexiones entrantes.
- `ESTABLISHED`: existe una conexión activa entre dos extremos.
- `TIME-WAIT`: la conexión se ha cerrado, pero el sistema mantiene temporalmente su estado para asegurar un cierre correcto.

Un puerto es un identificador lógico de una aplicación o servicio dentro de una máquina. Algunos puertos habituales son:

| Servicio | Puerto habitual |
|---|---:|
| SSH | 22 |
| HTTP | 80 |
| HTTPS | 443 |
| SMTP | 25 |
| DNS | 53 |
| FTP | 21 |
| IMAP | 143 o 993 con TLS |
| Proxy HTTP | 8080, aunque puede variar |

***

### Cortafuegos

Un cortafuegos filtra conexiones entrantes y salientes según reglas. Su objetivo es reducir la superficie de exposición: permitir únicamente el tráfico estrictamente necesario.

En sistemas actuales puedes encontrar:

- `nftables`, la arquitectura moderna de filtrado en Linux.
- `iptables`, herramienta histórica todavía muy presente.
- `ufw`, interfaz simplificada habitual en Ubuntu.
- `firewalld`, frecuente en Fedora, RHEL y distribuciones relacionadas.

Ejemplo básico con UFW:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw enable
sudo ufw status verbose
```

Esto bloquea por defecto conexiones entrantes, permite conexiones salientes y autoriza SSH por el puerto 22. Un cortafuegos no sustituye las actualizaciones, las contraseñas robustas, el control de accesos ni una configuración segura de los servicios.

***

## II. Fundamentos de redes

### Modelo OSI

El modelo OSI divide la comunicación de red en siete capas. Es un modelo conceptual que ayuda a entender la función de cada tecnología.

| Capa | Nombre | Función principal | Ejemplos |
|---:|---|---|---|
| 7 | Aplicación | Servicios utilizados por aplicaciones. | HTTP, DNS, SMTP |
| 6 | Presentación | Formato, cifrado y compresión de datos. | TLS, codificación |
| 5 | Sesión | Establecimiento y gestión de sesiones. | Control de sesiones |
| 4 | Transporte | Comunicación entre procesos y aplicaciones. | TCP, UDP |
| 3 | Red | Enrutamiento entre redes. | IP, ICMP, routers |
| 2 | Enlace de datos | Comunicación dentro de una red local. | Ethernet, MAC, switches |
| 1 | Física | Transmisión de bits por el medio físico. | Cable, fibra, radio, conectores |

En la práctica, Internet se basa principalmente en el modelo TCP/IP, que agrupa varias capas del modelo OSI.

### Encapsulación

Cuando una aplicación envía datos por la red, la información baja por las capas. Cada capa añade información de control, normalmente una cabecera.

Por ejemplo, al cargar una web:

1. La aplicación genera una solicitud HTTP.
2. TCP o UDP añade información de transporte, incluidos puertos.
3. IP añade direcciones IP de origen y destino.
4. Ethernet añade direcciones MAC para el siguiente salto local.
5. La capa física transmite los bits por cable, fibra o Wi-Fi.

En el receptor sucede el proceso inverso, denominado desencapsulación.

***

### Capa 1: física

La capa física transporta bits mediante señales eléctricas, ópticas o de radio.

Incluye elementos como:

- cable Ethernet;
- fibra óptica;
- señales Wi-Fi;
- conectores;
- repetidores y hubs antiguos;
- características físicas de transmisión.

Las topologías más conocidas son:

- **Bus**: todos los equipos comparten un mismo medio.
- **Anillo**: los equipos forman un circuito.
- **Estrella**: los dispositivos se conectan a un punto central, normalmente un switch.
- **Malla**: existen múltiples conexiones entre nodos para aumentar redundancia.

Actualmente, la topología en estrella es habitual en redes Ethernet domésticas y empresariales.

***

### Capa 2: enlace de datos

La capa de enlace permite la comunicación dentro de una red local o LAN.

- Cada interfaz de red tiene una dirección MAC.
- Ethernet es el protocolo más usado en redes cableadas.
- La unidad de datos de esta capa se llama **trama**.
- Un switch conecta dispositivos de una LAN y reenvía tramas según la dirección MAC de destino.

Una dirección MAC suele tener 48 bits y se representa en hexadecimal, por ejemplo:

```text
00:1A:2B:3C:4D:5E
```

El switch aprende qué direcciones MAC están asociadas a cada puerto observando las tramas que recibe. Así puede enviar una trama únicamente por el puerto adecuado en vez de reenviarla a todos los dispositivos.

***

### Direcciones IP privadas y públicas

Las direcciones IP privadas se utilizan dentro de redes locales y no se enrutan directamente por Internet.

Rangos IPv4 privados:

| Rango | Bloque CIDR |
|---|---|
| 10.0.0.0 – 10.255.255.255 | `10.0.0.0/8` |
| 172.16.0.0 – 172.31.255.255 | `172.16.0.0/12` |
| 192.168.0.0 – 192.168.255.255 | `192.168.0.0/16` |

Los dispositivos de una casa suelen tener IP privadas, mientras que el router dispone de una IP pública visible desde Internet. Normalmente utiliza NAT para traducir las conexiones internas y permitir que varios equipos compartan una misma IP pública.

Una máquina virtual puede tener una IP distinta de la máquina anfitriona, dependiendo de su configuración de red:

- **NAT**: la máquina virtual sale a Internet mediante la conexión del anfitrión.
- **Adaptador puente**: la máquina virtual aparece como otro dispositivo de la misma red local.
- **Red interna o solo-anfitrión**: útil para laboratorios aislados.

***

### Capa 3: red

La capa de red permite comunicar redes diferentes. Su protocolo principal es IP.

| Elemento | Función |
|---|---|
| Dirección IP | Identifica una interfaz dentro de una red. |
| Máscara de subred o prefijo CIDR | Distingue la parte de red y la parte de host de una IP. |
| Router | Reenvía paquetes entre redes. |
| Tabla de rutas | Indica qué camino o puerta de enlace usar para llegar a otros destinos. |
| Paquete o datagrama IP | Unidad de datos de la capa IP. |

Ejemplo:

```text
IP:      192.168.0.1
Máscara: 255.255.0.0
```

En binario:

```text
255.255.0.0  = 11111111.11111111.00000000.00000000
192.168.0.1  = 11000000.10101000.00000000.00000001
```

La máscara indica qué bits pertenecen a la red. En este caso, el prefijo es `/16`, por lo que la red es:

```text
192.168.0.0/16
```

Comandos actuales para consultar la configuración:

```bash
ip addr
ip route
```

Ejemplo de ruta por defecto:

```text
default via 192.168.1.1 dev wlan0
```

Esto significa que el tráfico destinado a redes desconocidas se enviará al router `192.168.1.1`.

Para observar los saltos de red hasta un destino:

```bash
traceroute example.com
```

En algunas distribuciones puede ser necesario instalarlo:

```bash
sudo apt install traceroute
```

***

### Capa 4: transporte

La capa de transporte permite que las aplicaciones se comuniquen entre sí mediante puertos.

| Protocolo | Características | Usos habituales |
|---|---|---|
| TCP | Orientado a conexión, fiable, ordenado y con control de errores. | Web, SSH, correo, transferencia de archivos. |
| UDP | No garantiza entrega ni orden, pero tiene menos sobrecarga. | DNS, streaming, videojuegos, VoIP. |

TCP utiliza un proceso de establecimiento de conexión conocido como *three-way handshake*:

1. El cliente envía `SYN`.
2. El servidor responde con `SYN-ACK`.
3. El cliente responde con `ACK`.

Así ambas partes confirman que pueden comunicarse antes de intercambiar datos.

Un servicio puede escuchar solo en `127.0.0.1`, la dirección de loopback. En ese caso, únicamente será accesible desde la propia máquina, no desde otros dispositivos de la red.

```bash
ss -lntp
```

Este comando permite ver servicios TCP en escucha y, si se ejecuta con permisos suficientes, el proceso asociado.

***

### Capa 7: aplicación

La capa de aplicación representa los protocolos y servicios utilizados directamente por programas de usuario.

Ejemplos:

- HTTP y HTTPS para la Web.
- DNS para resolver dominios a IP.
- SMTP, IMAP y POP3 para correo electrónico.
- SSH para administración remota.
- FTP o SFTP para transferencia de archivos.

***

### DHCP, DNS y HTTP

#### DHCP

DHCP asigna de forma automática parámetros de red a los dispositivos, entre ellos:

- dirección IP;
- máscara o prefijo de red;
- puerta de enlace predeterminada;
- servidores DNS;
- tiempo de concesión de la dirección.

Sin DHCP, habría que configurar estos valores manualmente en cada equipo.

#### DNS

DNS traduce nombres de dominio, como `www.ejemplo.com`, a direcciones IP. Es lo que permite navegar usando nombres legibles en vez de memorizar direcciones numéricas.

#### HTTP y HTTPS

HTTP es el protocolo que permite a un navegador solicitar recursos a un servidor web: páginas HTML, imágenes, scripts, archivos CSS o datos de APIs.

HTTPS es HTTP protegido por TLS. Añade cifrado, integridad y autenticación del servidor, por lo que evita que terceros puedan leer o modificar fácilmente la comunicación en tránsito.

***

## III. Ciberseguridad ofensiva y pentesting

El pentesting consiste en evaluar de forma autorizada la seguridad de sistemas, aplicaciones o redes. Su finalidad legítima es encontrar debilidades antes que un atacante y documentar cómo corregirlas.

No se debe escanear, interceptar tráfico ni probar vulnerabilidades sobre redes, servicios o dispositivos ajenos sin autorización expresa.

### Tipos de ataques

| Tipo | Descripción | Ejemplos |
|---|---|---|
| Ataques pasivos | Observan o recopilan información sin alterar directamente los sistemas. | Análisis de metadatos, reconocimiento, captura autorizada de tráfico. |
| Ataques activos | Modifican, interrumpen o intentan acceder a sistemas. | Denegación de servicio, suplantación, inyección SQL, secuestro de sesión. |
| Ataques de proximidad | Requieren cercanía física a la víctima o al entorno. | Shoulder surfing, robo de dispositivos, ingeniería social presencial. |
| Ataques internos | Los realiza alguien con acceso autorizado que abusa de sus privilegios. | Exfiltración de datos, instalación de software no autorizado, sabotaje. |
| Ataques a la cadena de suministro | Alteran software, hardware o actualizaciones antes de que lleguen al usuario final. | Dependencias comprometidas, actualizaciones maliciosas, firmware manipulado. |

***

### Fases de una evaluación de seguridad

Un proceso de pentesting responsable suele incluir las siguientes etapas:

1. **Reconocimiento**  
   Recopilación de información pública y autorizada sobre el objetivo: dominios, rangos IP, tecnologías, servicios, empleados o infraestructura expuesta.

2. **Descubrimiento y escaneo**  
   Identificación de hosts activos, puertos expuestos, servicios, versiones y configuraciones visibles.

3. **Enumeración**  
   Obtención más detallada de información de los servicios accesibles: recursos compartidos, configuraciones, usuarios expuestos o datos de versiones.

4. **Análisis de vulnerabilidades**  
   Comparación de software y configuraciones con vulnerabilidades conocidas, como CVE.

5. **Validación controlada**  
   En un entorno autorizado, se comprueba si una debilidad es explotable y cuál sería su impacto real.

6. **Informe y remediación**  
   Se documentan las evidencias, el impacto, la prioridad de cada hallazgo y las medidas correctoras.

7. **Revisión posterior**  
   Se verifica que los fallos se han corregido y que la solución no ha creado problemas adicionales.

En un pentest profesional, “borrar huellas” no es una fase legítima: las acciones deben quedar registradas para facilitar auditoría, análisis y corrección.

***

### Reconocimiento y análisis de red

Comandos útiles en un laboratorio propio:

```bash
ip addr
ip route
arp -a
ping 8.8.8.8
```

- `ip addr`: muestra las interfaces y direcciones configuradas.
- `ip route`: muestra la puerta de enlace y las rutas.
- `arp -a`: muestra asociaciones conocidas entre IP y direcciones MAC.
- `ping`: utiliza ICMP para comprobar conectividad y estimar latencia.

Ejemplos para conocer tu propia IP:

```bash
hostname -I
```

```bash
ipconfig getifaddr en0
```

El primer comando se usa habitualmente en Linux. El segundo es específico de macOS y obtiene la IP de la interfaz `en0`, que puede corresponder a Wi‑Fi en muchos equipos Apple.

Para comprobar puertos en escucha en macOS:

```bash
lsof -Pn -i4
```

***

### Escaneo de puertos, red y vulnerabilidades

| Tipo de análisis | Objetivo |
|---|---|
| Escaneo de red | Descubrir hosts activos dentro de un rango autorizado. |
| Escaneo de puertos | Identificar puertos abiertos, cerrados o filtrados. |
| Detección de servicios | Identificar qué servicio y versión responde en cada puerto. |
| Análisis de vulnerabilidades | Detectar posibles fallos conocidos o configuraciones inseguras. |

Nmap es una herramienta de administración y auditoría de red. Puede descubrir hosts, puertos y servicios en redes donde tengas permiso.

Ejemplos seguros para un laboratorio propio:

```bash
nmap -sn 192.168.1.0/24
```

Realiza descubrimiento de hosts sin hacer un escaneo de puertos convencional.

```bash
nmap -sV 192.168.1.50
```

Intenta identificar servicios y versiones en una máquina autorizada.

```bash
nmap -A 192.168.1.50
```

Activa varias funciones de detección, como versiones, scripts predeterminados, detección de sistema operativo y trazado de ruta. Es más intrusivo, por lo que debe usarse solo con autorización.

Nmap admite scripts NSE mediante `--script`; estos pueden ser categorías, directorios o ficheros Lua concretos. Algunos scripts pueden ser intrusivos, de modo que debes revisar qué hacen antes de ejecutarlos. [nmap](https://nmap.org/book/nse-usage.html)

Los resultados de un escaneo no equivalen automáticamente a una vulnerabilidad real. Una versión detectada puede dar falsos positivos, estar parcheada por el proveedor o no ser explotable debido a la configuración o segmentación de red.

***

### Enumeración de servicios

La enumeración busca información útil después de identificar un servicio accesible. Puede incluir:

- nombres de equipos;
- recursos compartidos;
- versiones de software;
- configuraciones expuestas;
- registros DNS;
- información de directorio, siempre dentro de un alcance autorizado.

Servicios que conviene comprender desde el punto de vista defensivo:

| Servicio | Puerto común | Riesgo si está mal configurado |
|---|---:|---|
| SMB/NetBIOS | 139, 445 | Recursos compartidos expuestos, permisos débiles o software obsoleto. |
| SNMP | UDP 161 | Divulgación de información de red mediante comunidades débiles o configuraciones inseguras. |
| DNS | 53 | Transferencias de zona no restringidas o exposición excesiva de infraestructura. |
| SMTP | 25, 465, 587 | Configuración incorrecta de relay o exposición de información. |
| LDAP | 389, 636 | Enumeración de directorio, credenciales mal protegidas o permisos excesivos. |
| NFS | 2049 | Recursos remotos expuestos con permisos inadecuados. |

Una buena defensa consiste en desactivar servicios innecesarios, aplicar el principio de mínimo privilegio, actualizar software, limitar el acceso por red y monitorizar registros.

***

### CVE y gestión de vulnerabilidades

Una CVE es un identificador público para una vulnerabilidad conocida. Su formato suele ser:

```text
CVE-año-número
```

Ejemplo:

```text
CVE-2024-XXXX
```

Una CVE no implica automáticamente que un sistema esté comprometido. Para evaluar el riesgo se debe comprobar:

- producto y versión afectados;
- configuración concreta;
- exposición del servicio;
- disponibilidad de parches;
- mitigaciones existentes;
- impacto potencial;
- probabilidad real de explotación.

Herramientas como OpenVAS/Greenbone, Nessus o Nikto pueden ayudar a detectar configuraciones o vulnerabilidades conocidas, pero sus resultados requieren validación manual.

***

### Captura de tráfico: Wireshark y tcpdump

Wireshark permite capturar y analizar tráfico de red de forma gráfica. Es útil para diagnosticar problemas, comprender protocolos y revisar comunicaciones de tu propio equipo o laboratorio.

Filtros de ejemplo:

```text
ip.addr == 192.168.1.50
```

Muestra tráfico hacia o desde esa IP.

```text
ip.addr == 192.168.1.50 && http
```

Muestra tráfico HTTP relacionado con esa IP. HTTP sin TLS transmite datos sin cifrar; HTTPS protege el contenido mediante TLS.

`tcpdump` permite capturar tráfico desde la línea de comandos:

```bash
sudo tcpdump -i eth0 -n port 80
```

- `-i eth0`: especifica la interfaz.
- `-n`: evita resolver nombres, mostrando IP y puertos numéricos.
- `port 80`: filtra tráfico HTTP no cifrado.

Nunca captures tráfico de terceras personas o de redes ajenas sin permiso explícito.

***

### ARP y ataques de intermediario

ARP traduce una dirección IPv4 local a una dirección MAC. En una red IPv4 Ethernet, un equipo puede preguntar:

> “¿Quién tiene la IP 192.168.1.1? Responde con tu dirección MAC”.

El envenenamiento ARP intenta manipular esas asociaciones para redirigir tráfico a través de un intermediario. Es un riesgo especialmente relevante en redes locales no segmentadas o Wi‑Fi abiertos.

Medidas de protección:

- utilizar HTTPS y validar certificados;
- usar VPN en redes no confiables;
- segmentar redes;
- usar protecciones de capa 2 en switches empresariales, como DHCP Snooping y Dynamic ARP Inspection;
- monitorizar cambios anómalos de asociaciones IP-MAC;
- evitar redes Wi‑Fi abiertas cuando sea posible.

***

### Malware, exploits y payloads

| Concepto | Significado |
|---|---|
| Vulnerabilidad | Debilidad en software, configuración o diseño. |
| Exploit | Técnica o código que aprovecha una vulnerabilidad. |
| Payload | Acción o código ejecutado después de lograr la ejecución. |
| Listener | Servicio que espera una conexión entrante, normalmente en un laboratorio. |
| Shell | Interfaz de línea de comandos obtenida en un sistema. |
| Reverse shell | La conexión se inicia desde la máquina objetivo hacia el sistema de pruebas. |
| Bind shell | El sistema objetivo queda escuchando en un puerto y el operador se conecta a él. |

Metasploit es un framework de pruebas de seguridad que organiza módulos para tareas de reconocimiento, explotación y pos-explotación. Debe utilizarse exclusivamente en sistemas propios, entornos de formación o con autorización contractual.

`msfvenom` es la herramienta de Metasploit para generar y codificar payloads; reemplazó a las herramientas antiguas `msfpayload` y `msfencode`. [docs.metasploit](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)

#### Payloads staged y stageless

Un payload **staged** se entrega en dos fases:

1. un componente inicial pequeño, llamado *stager*, establece la comunicación;
2. posteriormente se transfiere una segunda fase más completa.

Un payload *stageless* contiene toda la funcionalidad en un único archivo. Por ello suele ser mayor, pero no necesita descargar una segunda fase después de ejecutarse. Metasploit distingue, por ejemplo, `windows/meterpreter/reverse_tcp` como staged y `windows/meterpreter_reverse_tcp` como stageless. [docs.metasploit](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter-stageless-mode.html)

Esta distinción es importante para entender el funcionamiento técnico de los laboratorios, no para generar archivos contra sistemas ajenos.

***

## IV. Entornos de práctica: Hack The Box y TryHackMe

Hack The Box y TryHackMe ofrecen máquinas y laboratorios diseñados expresamente para aprender seguridad ofensiva y defensiva de forma legal.

Para acceder a laboratorios que requieren VPN, normalmente se utiliza un archivo de configuración OpenVPN:

```bash
sudo apt install openvpn
sudo openvpn --config archivo.ovpn
```

Cuando aparece un mensaje equivalente a “Initialization Sequence Completed”, significa que el túnel VPN se ha establecido correctamente.

Antes de empezar una máquina de laboratorio, conviene seguir una metodología:

1. Revisar el alcance y las normas de la plataforma.
2. Conectarse a la VPN si es necesaria.
3. Identificar la IP asignada a la máquina objetivo de laboratorio.
4. Realizar reconocimiento y enumeración dentro del entorno permitido.
5. Documentar los hallazgos.
6. Comprender la vulnerabilidad antes de probar una explotación.
7. Aplicar las conclusiones a medidas defensivas reales.

## Resumen esencial

- Linux gestiona usuarios, permisos y procesos mediante herramientas como `sudo`, `chmod`, `ps`, `top` y `systemctl`.
- SSH proporciona administración remota cifrada mediante autenticación, intercambio de claves y cifrado de la sesión. [openssh](https://www.openssh.org/manual.html)
- El modelo OSI separa la comunicación en capas; Ethernet opera principalmente en capa 2, IP en capa 3 y TCP/UDP en capa 4.
- Las direcciones MAC identifican interfaces dentro de una LAN; las direcciones IP permiten comunicar redes distintas.
- DHCP asigna configuración de red, DNS resuelve dominios e HTTP/HTTPS transporta contenido web.
- Nmap, Wireshark y tcpdump son herramientas útiles para diagnóstico y auditoría autorizada.
- Un escaneo o una CVE no prueban por sí mismos que exista una intrusión o que una vulnerabilidad sea explotable.
- Un pentest responsable termina con un informe, remediación y verificación, no con persistencia ni ocultación de rastros.
