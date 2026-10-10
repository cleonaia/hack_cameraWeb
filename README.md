# hack_cameraWeb


# Estructura para comprender el proyecto a realizar 

Este repositorio conserva dos objetivos de servir como material educativo y mantener las herramientas de laboratorio `ft_malcolm`, reconocimiento de cámaras y redes, escenarios ARP y el canal TLS

## Índice

1. [Linux](#1-linux)
2. [Redes](#2-fundamentos-de-redes)
3. [Pentesting en un laboratorio autorizado](#3-pentesting-en-un-laboratorio-autorizado)
4. [Hack The Box](#4-hack-the-box)
5. [Este repositorio y su laboratorio](#5-este-repositorio-y-su-laboratorio)
6. [Referencias](#6-referencias)

---

## 1. Linux

### 1.1 Usuarios, grupos y permisos

Linux permite que varias cuentas utilicen el mismo sistema. Cada proceso se ejecuta con los permisos de su usuario y sus grupos.`root` es la cuenta administrativa se usa en una cuenta normal y elevar privilegios solo para la operación que lo requiera. Lo cual  limita el impacto de errores y programas comprometidos.

| Comando | Uso |
|---|---|
| `whoami` | Muestra el usuario actual. |
| `id` | Muestra UID, GID y grupos. |
| `sudo comando` | Ejecuta un comando con privilegios administrativos, si la política lo permite. |
| `sudo -i` | Abre una sesión administrativa; sal con `exit`. |
| `adduser nombre` | Crea un usuario en distribuciones que incluyen esta herramienta. |
| `passwd nombre` | Cambia la contraseña de una cuenta. |
| `ls -l ruta` | Muestra propietario, grupo y permisos. |
| `chown usuario:grupo ruta` | Cambia propietario y grupo; normalmente requiere privilegios. |
| `chmod modo ruta` | Cambia los permisos. Comprueba el modo antes de aplicarlo a directorios compartidos. |



### 1.2 Instalar programas

En Debian y Ubuntu, APT resuelve e instala paquetes desde repositorios configurados. Los paquetes pueden depender de otros paquetes. `apt-get` sigue disponible para scripts; en una sesión interactiva suele usarse `apt`.

```bash
sudo apt update                 
apt search nombre              
apt show nombre             # Muestra los metadatos    
sudo apt install nombre         
```

Instala software desde fuentes confiables y revisa qué paquetes propone añadir o actualizar. Compilar desde código fuente es una alternativa distinta: requiere verificar el origen, las instrucciones y las dependencias del proyecto.

### 1.3 Procesos y actividad del sistema

Linux es multitarea. Estas herramientas permiten observar sesiones, procesos y recursos:

| Comando | Uso |
|---|---|
| `w` | Sesiones conectadas y carga del sistema. |
| `who` | Sesiones de usuario. |
| `ps -ef` | Instantánea de procesos del sistema. |
| `ps -ejH` | Procesos en forma de árbol. |
| `top` | Procesos y uso de recursos en tiempo real; `htop` es una alternativa si está instalada. |
| `jobs` | Trabajos en segundo plano de la shell actual. |
| `fg` | Devuelve un trabajo al primer plano. |
| `bg` | Reanuda en segundo plano un trabajo suspendido con `Ctrl+Z`. |

Para ejecutar una tarea en segundo plano en la shell actual, añade `&` al final. `nohup comando >salida.log 2>&1 &` permite que continúe tras cerrar esa terminal; para servicios persistentes, prefiere un gestor como `systemd`.

Apaga o reinicia una máquina propia desde una sesión administrativa con `sudo systemctl poweroff` o `sudo systemctl reboot`. Guarda antes el trabajo y comprueba que no haya tareas activas.

### 1.4 Acceso remoto con SSH

SSH cifra la sesión y autentica al servidor mediante su clave de host. La autenticación del usuario puede usar contraseña o claves. La primera conexión muestra la huella del servidor: verifícala por un canal confiable antes de aceptarla. El cifrado protege el transporte, pero no convierte una contraseña débil en una contraseña segura.

En Debian/Ubuntu se puede instalar el servidor en una VM propia:

```bash
sudo apt install openssh-server
sudo systemctl enable --now ssh
systemctl status ssh
```

Desde otra máquina autorizada:

```bash
ssh usuario@IP_DE_LA_VM
```

Para generar una clave personal:

```bash
ssh-keygen -t ed25519
ssh-copy-id usuario@IP_DE_LA_VM
```

Protege la clave privada y no la compartas. En un servidor expuesto, revisa la política de autenticación, limita quién puede conectarse y permite SSH en el firewall solo desde redes de administración.

### 1.5 Interfaces, conexiones y firewall

En Linux actual, `ip` y `ss` son las herramientas habituales; `ifconfig` y `netstat` pueden faltar o estar obsoletas.

```bash
ip addr                 # Interfaces y direcciones
ip route                # Tabla de rutas
ss -lntup               # Puertos TCP/UDP y procesos visibles
ss -tan                 # Conexiones TCP
```

En macOS, `ifconfig`, `netstat -rn` y `lsof -nP -i` permiten consultar interfaces, rutas y sockets. Los nombres de interfaz dependen del equipo y de sus adaptadores.

Un firewall aplica reglas de entrada, salida y reenvío. Usa la herramienta administrada por tu distribución —por ejemplo, `ufw` o `nftables`— y conserva una vía de recuperación antes de cambiar reglas remotamente. Empieza por una política documentada y permite únicamente el tráfico necesario. No copies reglas de firewall de Internet sin entender su efecto.

---

## 2. Fundamentos de redes

### 2.1 Modelo OSI
