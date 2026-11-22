# KernelPulse-eBPF

Herramienta de monitorización y observabilidad de seguridad a nivel de **Kernel de Linux** impulsada por tecnología **eBPF (Extended Berkeley Packet Filter)**. Diseñada para la detección de ejecución de procesos anómalos sin sobrecarga de rendimiento (*Zero Overhead*).

## Características del proyecto
- **Cero Espacio de Usuario Pesado:** Intercepta llamadas al sistema (`sys_enter_execve`) directamente en el espacio de ejecución del kernel.
- **Detección en Tiempo Real:** Captura instantánea de identificadores de procesos (PID), UID, comandos y rutas de binarios ejecutados.
- **Aislamiento de Seguridad:** No altera la estabilidad del sistema operativo y permite auditorías forenses de bajo nivel.

## Requisitos del Sistema
- Sistema operativo Linux con soporte para eBPF y encabezados de kernel (`linux-headers`).
- Python 3 y el paquete de herramientas BPF (`bcc`).

## Uso Técnico
```bash
sudo python3 src/kernel_probe.py