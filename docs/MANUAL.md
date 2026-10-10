# Manual técnico del laboratorio (edición 2026)

> **Implementación y alcance actuales:** las herramientas aceptan objetivos IPv4 de loopback o de rangos RFC 1918. El programa ARP en C también requiere que la interfaz seleccionada, la IP de origen suplantada y la IP objetivo pertenezcan a una misma subred privada. El escáner de cámaras limita cada ejecución a 4096 hosts. La red de Compose es interna. La revisión del código en macOS no ejecutó ningún escenario de red.

## 1. Arquitectura de red y fundamentos de protocolos

### 1.1 Capas OSI 2 y 3

- **Capa 2 (enlace de datos):** transmite tramas entre nodos del mismo segmento de red local (LAN). Los dispositivos se identifican mediante direcciones físicas o direcciones MAC (48 bits, 6 octetos).
- **Capa 3 (red):** reenvía paquetes y realiza el encaminamiento lógico entre redes distintas (IPv4: 32 bits, 4 octetos).

### 1.2 Protocolo de resolución de direcciones (ARP, RFC 826)

Para transportar paquetes IP en una red Ethernet o Wi‑Fi, estos se encapsulan en tramas de capa 2. Por ello, un equipo necesita conocer la dirección MAC del siguiente destino dentro de la subred local.

```
       Equipo A (192.168.1.10)                     Equipo B (192.168.1.1)
                 │                                            │
                 │ ── Solicitud ARP (ff:ff:ff:ff:ff:ff) ──> │
                 │    «¿Quién tiene 192.168.1.1?             │
                 │      Responde a 192.168.1.10»             │
                 │                                            │
                 │ <─ Respuesta ARP (unidifusión) ────────── │
                 │    «192.168.1.1 está en aa:bb:cc:dd:ee:01»│
                 ▼                                            ▼
```

### 1.3 Debilidad del protocolo ARP

ARP es un protocolo **sin estado y basado en la confianza**:

1. **No autentica las respuestas:** los equipos no comprueban mediante criptografía si quien responde está autorizado para reclamar una dirección IP.
2. **Respuestas no solicitadas (ARP gratuito):** muchos sistemas actualizan su caché ARP dinámica al recibir una respuesta, aunque no hayan enviado antes una solicitud.

---

## 2. Intermediario (MiTM) y funcionamiento de la suplantación ARP

### 2.1 Flujo del escenario

Al ejecutar `ft_malcolm`:

1. Escucha solicitudes ARP de difusión en la interfaz de red.
2. Cuando captura una solicitud de difusión, construye una respuesta ARP falsificada.
3. La respuesta indica al objetivo que `source_ip` (por ejemplo, la puerta de enlace) está asociada a `source_mac` (por ejemplo, la MAC del atacante).
4. La víctima puede enviar al atacante las tramas de capa 2 destinadas a la MAC anunciada para la puerta de enlace. El programa C no reenvía el tráfico IP.

El filtro C acepta cualquier solicitud ARP de difusión con campos Ethernet/IPv4 válidos; no compara la IP consultada con la IP de origen configurada. Envía la respuesta a la MAC objetivo configurada. Este comportamiento está cubierto por una prueba unitaria y se conserva por compatibilidad.

```mermaid
sequenceDiagram
    autonumber
    participant Objetivo as Víctima (10.42.0.20)
    participant Atacante as ft_malcolm (10.42.0.100)
    participant Gateway as Puerta de enlace (10.42.0.1)

    Objetivo->>Difusión: Solicitud ARP: «¿Quién tiene 10.42.0.1?»
    Atacante-->>Objetivo: Respuesta falsificada: «10.42.0.1 está en aa:bb:cc:dd:ee:10»
    Note over Objetivo: Actualiza la caché ARP: 10.42.0.1 -> MAC del atacante
    Objetivo->>Atacante: Envía tramas destinadas a la MAC del atacante
    Note over Atacante: ft_malcolm no reenvía tráfico IP; la herramienta Python activa el reenvío del kernel
```

---

## 3. Arquitectura de la implementación C

### 3.1 Estructura de archivos fuente

- `src/main.c`: comprobación de privilegios (`getuid`), análisis de argumentos, registro de señales y ciclo de vida del programa.
- `src/parser.c`: validación estricta de IPv4 decimal con puntos y direcciones MAC hexadecimales, resolución DNS de nombres de host y conversión de enteros de 32 bits. Los intervalos se validan entre 1 y 3 600 000 ms.
- `src/network.c`: detección de interfaz (`getifaddrs`), comprobaciones de subred privada y creación de sockets (`AF_PACKET` en Linux y `/dev/bpf*` en macOS).
- `src/arp.c`: construcción de tramas Ethernet/ARP (RFC 826), análisis de tramas, filtro de captura, inyección y anuncio ARP local de mejor esfuerzo al salir.
- `src/display.c`: salida formateada según los requisitos del subject de 42, inspección de paquetes y volcado hexadecimal de bytes.
- `src/utils.c`: gestión de señales y utilidades para temporización segura.

### 3.2 Compilación y opciones

```bash
make
make test
make debug
```

El `Makefile` fija C11 explícitamente para que un cambio en los valores predeterminados del compilador no altere silenciosamente el estándar del lenguaje. Se pueden seleccionar directorios de salida aislados mediante `BUILD_DIR`, `OBJ_DIR`, `NAME` y `TEST_NAME`.

---

## 4. Herramientas Python de reconocimiento y laboratorio

### 4.1 Detección de cámaras y flujos IoT (`camera_recon.py`)

- Escáner asíncrono multipuerto que consulta RTSP (554, 8554), ONVIF (80, 8080, 8899) e interfaces HTTP/HTTPS.
- Identifica indicios de fabricantes de cámaras: Hikvision, Dahua, Axis, Reolink, Foscam, Uniview, Hanwha, Mobotix y ESP32-CAM.
- Envía solicitudes RTSP `OPTIONS` y analiza cabeceras HTTP/RTSP seleccionadas. La lista de rutas RTSP declarada actualmente no se utiliza para comprobar flujos de vídeo.
- Acepta únicamente objetivos IPv4 de loopback/RFC 1918 y un máximo de 4096 hosts por ejecución.

```bash
python3 tools/camera_recon.py --target 192.168.1.0/24 --ports 80,554,8080,8554,8899
```

### 4.2 Motor MiTM en Python (`arp_poison.py`)

- Suplantación bidireccional entre el objetivo y la puerta de enlace.
- Activa el reenvío IP del kernel una vez que Scapy y las direcciones MAC se han resuelto; durante la limpieza restaura el valor anterior del reenvío.
- Aplica `--interface` a los envíos de Scapy e intenta enviar anuncios ARP al terminar.
- Limita el objetivo y la puerta de enlace a direcciones RFC 1918; aun así, utiliza únicamente una red virtual aislada.

```bash
sudo python3 tools/arp_poison.py --target 192.168.1.50 --gateway 192.168.1.1
```

### 4.3 Servicio TLS 1.3 autenticado para el laboratorio (`tls_shell.py`)

- Solo TLS 1.3. El listener se enlaza a loopback de forma predeterminada. `listen` y `connect` requieren uno o más destinos o subredes IPv4 explícitos mediante `--allowed-scope`; estos deben ser privados/locales. Pertenecer a RFC 1918 no implica por sí solo autorización. Se validan las respuestas DNS y la conexión se realiza a la IP validada.
- El agente debe proporcionar `--fingerprint` SHA-256 del certificado del listener; la fijación de huella es obligatoria. El listener autentica al agente mediante un desafío HMAC y el mismo secreto `FT_MALCOLM_TOKEN` en ambos extremos (al menos 32 bytes UTF-8).
- Las operaciones remotas permitidas son `!sysinfo`, `!pwd`, `!list` y `!exec date|id|uname|whoami`. No se permite ejecutar comandos de shell arbitrarios; los comandos se ejecutan sin shell.
- La carga y descarga de archivos se limita al directorio de un solo nivel `--file-root` (por defecto `./tls-transfer`), que debe tener permisos `0700`. Se rechazan enlaces simbólicos, enlaces duros y separadores de ruta; los archivos nuevos se crean de forma exclusiva y no se sobrescriben los existentes.
- Los mensajes llevan prefijo de longitud y tienen un límite de 32 MiB por trama; los archivos, un máximo de 16 MiB. El tiempo de espera es de 15 segundos para autenticación y 120 segundos para la sesión.
- La huella, el token y el protocolo con framing son obligatorios y no son compatibles con clientes antiguos. Actualiza ambos extremos y configura el secreto compartido antes de conectar.

```bash
# Configura el mismo secreto aleatorio (al menos 32 bytes) en cada VM por un canal separado.
export FT_MALCOLM_TOKEN='<secreto-compartido-de-al-menos-32-bytes>'
mkdir -p ./tls-transfer && chmod 700 ./tls-transfer

# En el controlador del laboratorio, enlazado a la interfaz privada:
python3 tools/tls_shell.py listen --bind 10.42.0.100 --allowed-scope 10.42.0.0/24 --port 4444 --file-root ./tls-transfer

# Copia la huella impresa y ejecútalo en el agente del laboratorio:
export FT_MALCOLM_TOKEN='<el-mismo-secreto-compartido>'
mkdir -p ./tls-transfer && chmod 700 ./tls-transfer
python3 tools/tls_shell.py connect --host 10.42.0.100 --allowed-scope 10.42.0.0/24 --port 4444 --fingerprint <sha256> --file-root ./tls-transfer
```

---

## 5. Instalación, dependencias y verificación

Las dependencias Python están declaradas en `pyproject.toml`; `requirements.txt` instala las versiones fijadas en `requirements.lock`. El archivo de bloqueo corresponde al entorno local Python 3.14.3 y Scapy 2.8.0. El rango declarado como compatible es Python 3.11–3.14; Python 3.15 queda excluido hasta verificar la matriz de dependencias. Instala las dependencias en un entorno virtual, nunca globalmente.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
make test
```

Las pruebas cubren el análisis C y el comportamiento de las tramas ARP, comprobaciones de ayuda y permisos de la CLI, además de la validación de alcance y el protocolo de tramas TLS en Python. No transmiten paquetes. La integración de Docker en ejecución no se ha verificado cuando Docker Engine no está disponible.

La red de Compose está marcada como `internal` y utiliza `10.42.0.0/24`. Los roles se comunican dentro de esa red, sin salida externa normal. Todos los contenedores eliminan primero sus capacidades: el servicio `attacker` (atacante) añade `NET_ADMIN`/`NET_RAW`, `victim` (víctima) añade únicamente `NET_RAW` para `ping` y `gateway` (puerta de enlace) no añade ninguna. Los contenedores tienen sistemas de archivos raíz de solo lectura, `no-new-privileges` y montajes de solo lectura de los archivos de código necesarios; la compilación se realiza en `/tmp` dentro del contenedor atacante. El comportamiento en ejecución de Docker debe probarse en un host que tenga Docker instalado.

---

## 6. Seguridad y medidas defensivas

Para proteger una red contra la suplantación ARP:

1. **Dynamic ARP Inspection (DAI):** switches empresariales pueden comparar paquetes ARP con la base de asociaciones de DHCP snooping y descartar los que no sean válidos.
2. **Tablas ARP estáticas:** en servidores críticos y puertas de enlace se pueden fijar asociaciones IP-MAC estáticas, considerando el coste de mantenimiento.
3. **Control de acceso 802.1X:** autentica dispositivos antes de permitirles acceder a dominios de difusión de capa 2.
4. **Cifrado de extremo a extremo:** TLS/HTTPS, SSH y VPN protegen los datos de aplicación aunque la capa 2 se vea comprometida.
