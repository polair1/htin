#!/usr/bin/env python3
"""
HTML Injection Scanner v1.0
Herramienta para detectar vulnerabilidades de inyección HTML

ADVERTENCIA LEGAL:
Solo usar en aplicaciones propias o con autorización explícita por escrito.
El uso no autorizado es ILEGAL y puede resultar en acciones legales.

Uso: python3 htin2.py [opciones]
"""

import os
import sys
import json
import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import time
from datetime import datetime

__version__ = "1.0.0"
__author__ = "Security Researcher"

class Colors:
    """Códigos de color ANSI para terminal"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

    @staticmethod
    def disable():
        """Desactivar colores (para archivos)"""
        Colors.RED = ''
        Colors.GREEN = ''
        Colors.YELLOW = ''
        Colors.BLUE = ''
        Colors.MAGENTA = ''
        Colors.CYAN = ''
        Colors.WHITE = ''
        Colors.BOLD = ''
        Colors.END = ''


class HTMLInjectionScanner:
    def __init__(self, timeout=15, verbose=False, delay=0.5):
        self.timeout = timeout
        self.verbose = verbose
        self.delay = delay
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        
        # Payloads organizados por nivel de riesgo
        self.payloads = {
            'basic': [
                '<b>test</b>',
                '<h1>test</h1>',
                '<div>test</div>',
            ],
            'styled': [
                '<div style="color:red">test</div>',
                '<span style="background:yellow">test</span>',
            ],
            'dangerous': [
                '<img src="x">',
                '<iframe src="about:blank"></iframe>',
                '<svg onload=console.log(1)>',
            ],
            'xss': [
                '<script>console.log("XSS")</script>',
                '<img src=x onerror=alert(1)>',
                '<body onload=alert(1)>',
                '<svg/onload=alert(1)>',
            ]
        }
        
        self.stats = {
            'total_tested': 0,
            'vulnerabilities_found': 0,
            'forms_tested': 0,
            'params_tested': 0
        }
    
    def log(self, message, level='info'):
        """Sistema de logging con colores"""
        prefix = {
            'info': f'{Colors.BLUE}[*]{Colors.END}',
            'success': f'{Colors.GREEN}[✓]{Colors.END}',
            'warning': f'{Colors.YELLOW}[!]{Colors.END}',
            'error': f'{Colors.RED}[✗]{Colors.END}',
            'vuln': f'{Colors.RED}{Colors.BOLD}[!]{Colors.END}',
        }
        print(f"{prefix.get(level, '[*]')} {message}")
    
    def is_vulnerable(self, original_response, injected_response, payload):
        """Detecta si la inyección fue exitosa"""
        # Método 1: Payload reflejado sin sanitizar
        if payload in injected_response:
            return True, "Payload reflejado sin sanitización"
        
        # Método 2: Buscar etiquetas HTML inyectadas
        try:
            soup = BeautifulSoup(injected_response, 'html.parser')
            dangerous_tags = ['script', 'iframe', 'img', 'svg', 'object', 'embed']
            
            for tag in dangerous_tags:
                elements = soup.find_all(tag)
                for elem in elements:
                    elem_str = str(elem).lower()
                    if 'test' in elem_str or 'xss' in elem_str or 'console.log' in elem_str:
                        return True, f"Etiqueta <{tag}> inyectada detectada en DOM"
        except:
            pass
        
        # Método 3: Buscar patrones HTML del payload
        pattern = re.escape(payload.replace('test', '').replace('XSS', '').replace('console.log', ''))
        if len(pattern) > 5 and re.search(pattern, injected_response, re.IGNORECASE):
            return True, "Estructura HTML del payload encontrada"
        
        return False, "No vulnerable"
    
    def test_url_parameter(self, url, param, value, payload_levels=['basic', 'styled']):
        """Prueba inyección en parámetro de URL"""
        vulnerabilities = []
        
        for level in payload_levels:
            if level not in self.payloads:
                continue
                
            for i, payload in enumerate(self.payloads[level], 1):
                try:
                    params = {param: payload}
                    response = self.session.get(url, params=params, timeout=self.timeout)
                    self.stats['total_tested'] += 1
                    
                    vulnerable, reason = self.is_vulnerable('', response.text, payload)
                    
                    if vulnerable:
                        self.log(f"Vulnerable: Parámetro '{param}' con payload nivel {level}", 'vuln')
                        vulnerabilities.append({
                            'type': 'url_parameter',
                            'parameter': param,
                            'payload': payload,
                            'reason': reason,
                            'level': level,
                            'url': response.url
                        })
                        self.stats['vulnerabilities_found'] += 1
                        
                        if self.verbose:
                            self.log(f"  Payload: {payload[:80]}", 'info')
                            self.log(f"  Razón: {reason}", 'info')
                    elif self.verbose:
                        self.log(f"  Payload {level}:{i} bloqueado", 'success')
                    
                    time.sleep(self.delay)
                    
                except requests.exceptions.RequestException as e:
                    if self.verbose:
                        self.log(f"Error de red: {str(e)}", 'error')
                except Exception as e:
                    if self.verbose:
                        self.log(f"Error inesperado: {str(e)}", 'error')
        
        return vulnerabilities
    
    def test_form(self, url, form, payload_levels=['basic', 'styled']):
        """Prueba inyección en formulario"""
        vulnerabilities = []
        
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        target_url = urljoin(url, action)
        
        # Extraer campos de entrada
        inputs = form.find_all('input')
        textareas = form.find_all('textarea')
        
        fields = []
        hidden_fields = {}
        
        for inp in inputs:
            name = inp.get('name')
            input_type = inp.get('type', 'text')
            
            if name:
                if input_type == 'hidden':
                    hidden_fields[name] = inp.get('value', '')
                elif input_type not in ['submit', 'button', 'image']:
                    fields.append(name)
        
        for textarea in textareas:
            name = textarea.get('name')
            if name:
                fields.append(name)
        
        if not fields:
            if self.verbose:
                self.log("No se encontraron campos testables", 'warning')
            return []
        
        self.log(f"Campos a probar: {', '.join(fields)}", 'info')
        
        # Probar cada campo
        for field in fields:
            for level in payload_levels:
                if level not in self.payloads:
                    continue
                
                for payload in self.payloads[level]:
                    try:
                        data = hidden_fields.copy()
                        data[field] = payload
                        
                        if method == 'post':
                            response = self.session.post(target_url, data=data, timeout=self.timeout)
                        else:
                            response = self.session.get(target_url, params=data, timeout=self.timeout)
                        
                        self.stats['total_tested'] += 1
                        
                        vulnerable, reason = self.is_vulnerable('', response.text, payload)
                        
                        if vulnerable:
                            self.log(f"Vulnerable: Campo '{field}' con payload nivel {level}", 'vuln')
                            vulnerabilities.append({
                                'type': 'form_field',
                                'field': field,
                                'payload': payload,
                                'reason': reason,
                                'level': level,
                                'method': method.upper(),
                                'url': target_url
                            })
                            self.stats['vulnerabilities_found'] += 1
                            
                            if self.verbose:
                                self.log(f"  Payload: {payload[:80]}", 'info')
                        
                        time.sleep(self.delay)
                        
                    except Exception as e:
                        if self.verbose:
                            self.log(f"Error: {str(e)}", 'error')
        
        return vulnerabilities
    
    def scan_url(self, url, payload_levels=['basic', 'styled', 'dangerous']):
        """Escanea una URL completa"""
        self.log(f"Iniciando escaneo de: {url}", 'info')
        all_vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Buscar formularios
            forms = soup.find_all('form')
            self.log(f"Formularios encontrados: {len(forms)}", 'info')
            
            for idx, form in enumerate(forms, 1):
                self.log(f"\n--- Analizando formulario {idx}/{len(forms)} ---", 'info')
                self.stats['forms_tested'] += 1
                vulns = self.test_form(url, form, payload_levels)
                all_vulnerabilities.extend(vulns)
            
            # Analizar parámetros URL si existen
            parsed = urlparse(url)
            if parsed.query:
                self.log(f"\nParámetros URL detectados", 'info')
                self.stats['params_tested'] += 1
                # Aquí podrías implementar pruebas de parámetros
            
        except requests.exceptions.RequestException as e:
            self.log(f"Error accediendo a la URL: {str(e)}", 'error')
        except Exception as e:
            self.log(f"Error inesperado: {str(e)}", 'error')
        
        return all_vulnerabilities
    
    def generate_report(self, vulnerabilities, url, output_file=None):
        """Genera reporte detallado"""
        report = {
            'scan_info': {
                'target': url,
                'timestamp': datetime.now().isoformat(),
                'scanner_version': __version__,
                'statistics': self.stats
            },
            'vulnerabilities': vulnerabilities
        }
        
        # Reporte en consola
        print(f"\n{'='*70}")
        print(f"{Colors.BOLD}REPORTE DE ESCANEO{Colors.END}")
        print(f"{'='*70}")
        print(f"\nURL objetivo: {Colors.CYAN}{url}{Colors.END}")
        print(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\n{Colors.BOLD}ESTADÍSTICAS:{Colors.END}")
        print(f"  • Tests realizados: {self.stats['total_tested']}")
        print(f"  • Formularios analizados: {self.stats['forms_tested']}")
        print(f"  • Vulnerabilidades encontradas: {Colors.RED}{self.stats['vulnerabilities_found']}{Colors.END}")
        
        if vulnerabilities:
            print(f"\n{Colors.BOLD}VULNERABILIDADES DETECTADAS:{Colors.END}\n")
            
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"{Colors.RED}[{i}]{Colors.END} Tipo: {vuln['type']}")
                
                if vuln['type'] == 'form_field':
                    print(f"    Campo: {vuln['field']}")
                    print(f"    Método: {vuln['method']}")
                elif vuln['type'] == 'url_parameter':
                    print(f"    Parámetro: {vuln['parameter']}")
                
                print(f"    Nivel: {Colors.YELLOW}{vuln['level'].upper()}{Colors.END}")
                print(f"    Payload: {vuln['payload'][:100]}")
                print(f"    Razón: {vuln['reason']}")
                print(f"    URL: {vuln['url'][:80]}...")
                print()
            
            print(f"{Colors.BOLD}RECOMENDACIONES:{Colors.END}")
            print("""
    1. Sanitizar TODAS las entradas del usuario
    2. Usar HTML encoding para todas las salidas
    3. Implementar Content Security Policy (CSP)
    4. Validar tipos de datos en el servidor
    5. Usar frameworks con protección anti-XSS incorporada
    6. Implementar Web Application Firewall (WAF)
    7. Realizar auditorías de seguridad regulares
            """)
        else:
            print(f"\n{Colors.GREEN}✓ No se encontraron vulnerabilidades de HTML Injection{Colors.END}")
        
        # Guardar a archivo si se especificó
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=2, ensure_ascii=False)
                self.log(f"Reporte guardado en: {output_file}", 'success')
            except Exception as e:
                self.log(f"Error guardando reporte: {str(e)}", 'error')
        
        print(f"{'='*70}\n")
        
        return report


def print_banner():
    """Muestra el banner de la herramienta"""
    banner = f"""
{Colors.CYAN}{'='*70}
██╗  ██╗████████╗███╗   ███╗██╗         ███████╗ ██████╗ █████╗ ███╗   ██╗
██║  ██║╚══██╔══╝████╗ ████║██║         ██╔════╝██╔════╝██╔══██╗████╗  ██║
███████║   ██║   ██╔████╔██║██║         ███████╗██║     ███████║██╔██╗ ██║
██╔══██║   ██║   ██║╚██╔╝██║██║         ╚════██║██║     ██╔══██║██║╚██╗██║
██║  ██║   ██║   ██║ ╚═╝ ██║███████╗    ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{'='*70}
    HTML Injection Vulnerability Scanner v{__version__}
    {Colors.YELLOW}⚠️  Solo para uso autorizado - Uso ilegal está prohibido{Colors.END}
{'='*70}{Colors.END}
    """
    print(banner)


def main():
    parser = argparse.ArgumentParser(
        description='Scanner de vulnerabilidades HTML Injection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python3 html_scanner.py -u http://testphp.vulnweb.com
  python3 html_scanner.py -u http://localhost/dvwa -v
  python3 html_scanner.py -u http://ejemplo.com -l basic styled -o reporte.json
  python3 html_scanner.py -u http://ejemplo.com --no-color
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='URL objetivo a escanear')
    parser.add_argument('-v', '--verbose', action='store_true', help='Modo verbose (más detalles)')
    parser.add_argument('-l', '--levels', nargs='+', 
                       choices=['basic', 'styled', 'dangerous', 'xss'],
                       default=['basic', 'styled', 'dangerous'],
                       help='Niveles de payload a probar')
    parser.add_argument('-o', '--output', help='Archivo para guardar el reporte (JSON)')
    parser.add_argument('-t', '--timeout', type=int, default=15, help='Timeout en segundos (default: 15)')
    parser.add_argument('-d', '--delay', type=float, default=0.5, help='Delay entre peticiones (default: 0.5)')
    parser.add_argument('--no-color', action='store_true', help='Desactivar colores en la salida')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    
    args = parser.parse_args()
    
    # Desactivar colores si se solicita
    if args.no_color:
        Colors.disable()
    
    # Mostrar banner
    print_banner()
    
    # Advertencia legal
    print(f"{Colors.RED}{Colors.BOLD}ADVERTENCIA LEGAL:{Colors.END}")
    print(f"{Colors.YELLOW}Esta herramienta solo debe usarse en aplicaciones donde tengas")
    print(f"autorización EXPLÍCITA por escrito. El uso no autorizado es ILEGAL.{Colors.END}\n")
    
    confirmation = input(f"¿Tienes autorización para escanear {args.url}? (si/no): ").strip().lower()
    if confirmation != 'si':
        print(f"\n{Colors.RED}Operación cancelada. Debes tener autorización explícita.{Colors.END}")
        sys.exit(0)
    
    print()
    
    # Validar URL
    url = args.url
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Crear scanner
    scanner = HTMLInjectionScanner(
        timeout=args.timeout,
        verbose=args.verbose,
        delay=args.delay
    )
    
    # Ejecutar escaneo
    try:
        vulnerabilities = scanner.scan_url(url, payload_levels=args.levels)
        scanner.generate_report(vulnerabilities, url, output_file=args.output)
        
        # Código de salida según resultados
        sys.exit(1 if vulnerabilities else 0)
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Escaneo interrumpido por el usuario{Colors.END}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Colors.RED}Error fatal: {str(e)}{Colors.END}")
        sys.exit(1)


if __name__ == "__main__":
    main()
