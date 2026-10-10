# Análisis de una webcam en un laboratorio local

## Acerca del proyecto

Práctica educativa de ciberseguridad realizada desde una máquina virtual Kali Linux para analizar **una webcam propia dentro de una red local controlada**. El ejercicio estudia cómo una técnica de intermediario basada en suplantación ARP puede afectar al tráfico de la LAN y cómo observar ese tráfico con herramientas de análisis.

El flujo de aprendizaje utiliza **Ettercap** para la demostración MiTM, **Wireshark** para inspeccionar paquetes y **Metasploit** como herramienta de laboratorio complementaria. Son herramientas externas: este repositorio no las integra ni automatiza su uso.

> Realiza la práctica únicamente con equipos de tu propiedad, en una red aislada o expresamente autorizada. No captures tráfico de terceros ni pruebes en redes públicas, domésticas compartidas o corporativas.

## Objetivos de aprendizaje

- Entender la relación entre direcciones IP, MAC, ARP y tramas Ethernet.
- Observar cómo una modificación de la caché ARP puede alterar la ruta local del tráfico.
- Analizar paquetes capturados y reconocer los límites de lo que una captura permite concluir.
- Comprender por qué TLS y la validación de certificados protegen las comunicaciones de aplicación.
- Practicar documentación, alcance autorizado y restauración del entorno.

## Entorno de práctica

El escenario conceptual consta de una VM Kali, una webcam propia y la infraestructura de red local necesaria para comunicar ambas. Para reducir riesgos, utiliza una red virtual aislada con snapshots y sin puente hacia redes ajenas. Confirma antes de empezar qué interfaces pertenecen al laboratorio y limita la captura a ese segmento.

Ettercap, Wireshark y Metasploit se instalan y ejecutan por separado siguiendo su documentación oficial. Este README describe el propósito educativo del ejercicio; no es una guía para interceptar dispositivos o tráfico fuera del laboratorio.

## Recorrido del ejercicio

1. **Preparación:** delimita los dispositivos autorizados, registra la topología y crea puntos de restauración.
2. **Fundamentos:** identifica las direcciones IP y MAC de los equipos del laboratorio y revisa el papel de ARP.
3. **Demostración controlada:** estudia el efecto de la suplantación ARP en la red aislada, sin ampliar el alcance.
4. **Observación:** utiliza Wireshark para examinar únicamente tráfico generado por el ejercicio. Protege las capturas porque pueden contener información sensible.
5. **Análisis:** documenta qué observaste, qué no puede concluirse solo con la captura y cómo el cifrado TLS afecta a la visibilidad del contenido.
6. **Cierre:** detén las herramientas, restaura las VMs y comprueba que la red volvió a su estado inicial.

## Conceptos relacionados

### ARP y MiTM

ARP resuelve direcciones IPv4 a direcciones MAC dentro de un enlace local. El protocolo no autentica criptográficamente sus respuestas. Una respuesta manipulada puede hacer que un equipo asocie temporalmente una IP con una MAC distinta. El impacto depende de la topología, las defensas de la red y de si el tráfico está cifrado.

### Captura de tráfico

Wireshark permite inspeccionar protocolos y metadatos de paquetes. Una captura no siempre revela el contenido de una comunicación: HTTPS y otros protocolos cifrados protegen los datos de aplicación, aunque algunos metadatos de red sigan visibles. Trata los archivos PCAP como información confidencial.

### Metasploit

Metasploit es un framework modular externo para formación y pruebas autorizadas. En este proyecto se menciona como parte del contexto de aprendizaje; no existe una integración propia ni se incluyen módulos, payloads o automatizaciones de Metasploit.

## Contenido del repositorio

El repositorio contiene material y herramientas complementarias para estudiar redes y ciberseguridad: reconocimiento de servicios locales, escenarios ARP, una herramienta C didáctica (`ft_malcolm`), un canal TLS de laboratorio y una configuración Docker. Estos componentes no sustituyen a Ettercap, Wireshark o Metasploit ni representan por sí solos el flujo descrito arriba.

Consulta el [manual técnico](docs/MANUAL.md) para conocer el alcance y el comportamiento real de cada componente. La configuración Docker requiere Docker Engine y Compose; no se afirma que funcione en un sistema donde no se haya ejecutado.

## Compilación y pruebas del código

Requisitos: compilador compatible con C11, `make`, Bash y una versión de Python admitida por `pyproject.toml`. Para mantener aisladas las dependencias Python:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

```bash
make
make test
```

Las pruebas automáticas validan componentes C, comprobaciones CLI y herramientas Python. No realizan envenenamiento ARP, escaneos ni pruebas contra una webcam.

## Referencias

- [Documentación de Ettercap](https://www.ettercap-project.org/)
- [Wireshark](https://www.wireshark.org/docs/)
- [Documentación de Metasploit](https://docs.metasploit.com/)
- [RFC 826: ARP](https://datatracker.ietf.org/doc/html/rfc826)
- [Manual técnico del laboratorio](docs/MANUAL.md)
