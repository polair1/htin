# 🛡️ HTML Injection Scanner

![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-1.1.0-orange)

Herramienta profesional en **Python 3** para detectar vulnerabilidades de **inyección HTML** y **Cross-Site Scripting (XSS)** en aplicaciones web.

---

## ⚠️ Advertencia Legal

Esta herramienta está diseñada **EXCLUSIVAMENTE** para:
- Pruebas de penetración **autorizadas**
- Auditorías de seguridad **con permiso explícito**
- **Entornos de prueba** y desarrollo propios
- Propósitos **educativos y de investigación**

> **El uso no autorizado es ILEGAL** y puede resultar en sanciones penales o civiles.  
> El autor **no se hace responsable** del mal uso de esta herramienta.

---

## ✨ Características

- ✅ Detección de **inyección HTML** y **XSS reflejado**
- ✅ Análisis automático de **formularios y parámetros GET/POST**
- ✅ **Múltiples niveles de payloads** (basic, styled, dangerous, xss)
- ✅ **Reportes JSON** con detalles de cada hallazgo
- ✅ **Interfaz colorida** en consola
- ✅ **Modo verbose** para debugging
- ✅ **Configuración flexible** (timeout, delay, etc.)
- ✅ 100% hecho en **Python puro** — sin dependencias de navegador

---

## 🚀 Instalación Rápida

### Método 1: Usando `pip` (recomendado)

```bash
# Clonar el repositorio
git clone https://github.com/polair1/htin.git
cd htin

# Instalar dependencias
pip install -r requirements.txt

# O instalar en modo editable
pip install -e .
