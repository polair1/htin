# Opciones Detalladas
# -u, --url (REQUERIDO)
URL del objetivo a escanear.
Ejemplos:
python3 htin2.py -u http://example.com
python3 htin2.py -u https://testphp.vulnweb.com/search.php


# -v, --verbose
Activa modo detallado con más información.
Ejemplo:
python3 htin2.py -u http://example.com -v
Salida con verbose:
[*] Probando payload basic:1 bloqueado
[*] Probando payload basic:2 bloqueado
[!] VULNERABLE con payload basic:3
  Payload: <h1>test</h1>
  Razón: Payload reflejado sin sanitización


# -l, --levels
Especifica qué niveles de payload probar.
Opciones: basic, styled, dangerous, xss
Ejemplos:
# Solo payloads básicos y con estilos
python3 htin2.py -u http://example.com -l basic styled

# Todos los niveles (incluye XSS)
python3 htin2.py -u http://example.com -l basic styled dangerous xss

# -o, --output
Guarda el reporte en formato JSON.
Ejemplo:
python3 htin2.py -u http://example.com -o reporte_2025.json
Formato del JSON:
json{
  "scan_info": {
    "target": "http://example.com",
    "timestamp": "2025-09-29T10:30:00",
    "statistics": {
      "total_tested": 45,
      "vulnerabilities_found": 3
    }
  },
  "vulnerabilities": [...]
}
# -t, --timeout
Tiempo máximo de espera por petición (segundos).
Ejemplo:
python3 htin2.py -u http://slow-site.com -t 30

# -d, --delay
Pausa entre peticiones (segundos).
Ejemplo:
# Escaneo más rápido (0.2 segundos)
python3 htin2.py -u http://example.com -d 0.2

# Escaneo más lento para no saturar (2 segundos)
python3 htin2.py -u http://example.com -d 2

# --no-color
Desactiva colores ANSI (útil para logs).
Ejemplo:
python3 htin2.py -u http://example.com --no-color > scan.log
