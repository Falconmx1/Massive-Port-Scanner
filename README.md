# Massive Port Scanner 🚀

**Escáner de puertos ultrarrápido en Python que explora los 10,000 puertos más comunes en segundos.**

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://python.org)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

Herramienta de auditoría de red desarrollada en Python utilizando `asyncio` para alcanzar un rendimiento extremo sin necesidad de threads pesados. Ideal para pentesting, administradores de sistemas y entusiastas de la seguridad.

---

## ⚡ Características principales

- 🚀 **Ultra-rápido**: Escanea los 10,000 puertos más comunes en segundos.
- 🔄 **Arquitectura asíncrona**: Usa `asyncio` para conexiones no bloqueantes.
- 🎯 **Múltiples objetivos**: Soporte para IPs individuales, rangos CIDR y archivos de lista.
- ⏱️ **Control de tiempo**: Ajusta el timeout por puerto.
- 📊 **Múltiples formatos**: Exporta resultados en JSON y CSV.
- 🛡️ **Control de concurrencia**: Evita saturar tu sistema o la red objetivo.
- 📝 **Logs detallados**: Muestra el progreso en tiempo real.

---

## 🛠 Instalación

### Requisitos previos
- Python 3.7 o superior
- pip (gestor de paquetes de Python)

### Pasos de instalación

```bash
# Clonar el repositorio
git clone https://github.com/Falconmx1/Massive-Port-Scanner.git

# Entrar al directorio
cd Massive-Port-Scanner

# Instalar dependencias (no requiere librerías externas)
pip install -r requirements.txt

📖 Uso básico
Escaneo de una IP individual

python scanner.py -t 192.168.1.1 -p 1000 -o reporte.json

Escaneo de un rango CIDR

python scanner.py -t 192.168.1.0/24 -p 500 --format csv -o scan_red.csv

Escaneo desde un archivo de IPs

python scanner.py -t ips.txt -p 2000 -o resultados.json

Parámetros disponibles

Parámetro                                    Descripción                                                   Valor por defecto
-t, --target                                 IP, rango CIDR o archivo .txt                                 Requerido
-p, --ports                                  Número de puertos a escanear (usa los más comunes)            1000
--timeout                                    Tiempo de espera por puerto en segundos                       1.5
--concurrency                                Nivel de concurrencia (tareas simultáneas)                    500
-o, --output                                 Archivo de salida para resultados                             None
--format                                     Formato de salida: json o csv                                 json
                                                        
📊 Ejemplos de salida

Formato JSON
{
    "target": "192.168.1.1",
    "scan_date": "2026-07-19T15:30:45.123456",
    "open_ports": [22, 80, 443, 3306],
    "total_open": 4
}

Formato CSV
IP,Puerto
192.168.1.1,22
192.168.1.1,80
192.168.1.1,443
192.168.1.1,3306

🔧 Personalización avanzada
Modificar la lista de puertos
Puedes editar la variable COMMON_PORTS en scanner.py para usar tu propia lista de puertos.

Ajustar la concurrencia
Si tienes una conexión de red muy rápida, puedes aumentar el valor de --concurrency para acelerar el escaneo:
python scanner.py -t 192.168.1.1 -p 10000 --concurrency 1000

⚠️ Aviso Legal
El uso de esta herramienta debe limitarse EXCLUSIVAMENTE a:

Entornos controlados (tu propia red).

Sistemas donde tengas autorización expresa por escrito.

Fines educativos y de aprendizaje sobre seguridad informática.

El autor no se hace responsable del uso indebido de esta herramienta. Escanear sistemas sin permiso es ilegal en la mayoría de los países.

🤝 Contribuciones
¡Las contribuciones son bienvenidas! Si tienes ideas para mejorar el escáner:

1. Haz un fork del proyecto.

2. Crea tu rama de características (git checkout -b feature/AmazingFeature).

3. Haz commit de tus cambios (git commit -m 'Add some AmazingFeature').

4. Push a la rama (git push origin feature/AmazingFeature).

5. Abre un Pull Request.

📜 Licencia
Este proyecto está bajo la licencia GNU General Public License v3.0. Consulta el archivo LICENSE para más detalles.

📧 Contacto
Autor: Falconmx1

GitHub: @Falconmx1

🙏 Agradecimientos
A la comunidad de Python por su increíble ecosistema.

A todos los que reportan issues y contribuyen al proyecto.
                               
