# Massive Port Scanner 🚀
**Escáner paralelo de 10,000 puertos en segundos.**

Herramienta de auditoría de red desarrollada en Python utilizando `asyncio` para alcanzar un rendimiento extremo sin necesidad de threads pesados.

## ⚡ Características
- Escaneo de los **Top 10,000 puertos** más comunes.
- Soporte para **IPs individuales** (ej. `192.168.1.1`), **rangos CIDR** (ej. `192.168.1.0/24`) y **archivos de lista**.
- Control de tiempo de espera (`timeout`) ajustable.
- Salida en formato **JSON** y **CSV** para reportes.

## 🛠 Instalación
```bash
git clone https://github.com/Falconmx1/Massive-Port-Scanner.git
cd Massive-Port-Scanner
pip install -r requirements.txt
