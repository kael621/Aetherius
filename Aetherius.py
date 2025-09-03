import requests
from bs4 import BeautifulSoup
import subprocess
import re
import urllib.parse
from urllib.parse import urljoin
import os
import customtkinter as ctk
import threading
import queue
import sys
from concurrent.futures import ThreadPoolExecutor

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

ascii_art = """
   .:'    Dragon                        `:.
  ::'       Art by                       `::
 :: :.    Ronald Allan Stanions         .: ::
  `:. `:.             .             .:'  .:'
   `::. `::           !           ::' .::'
       `::.`::.    .' ! `.    .::'.::'
         `:.  `::::'':!:``::::'   ::'
         :'*:::.  .:' ! `:.  .:::*`:
        :: HHH::.   ` ! '   .::HHH ::
       ::: `H TH::.  `!'  .::HT H' :::
       ::..  `THHH:`:   :':HHHT'  ..::
       `::      `T: `. .' :T'      ::'
         `:. .   :         :   . .:'
           `::'               `::'
             :'  .`.  .  .'.  `:
             :' ::.       .:: `:
             :' `:::     :::' `:
              `.  ``     ''  .'
               :`...........':
               ` :`.     .': '
                `:  `":"':::  

     \           |    |                 _)              
    _ \     _ \  __|  __ \    _ \   __|  |  |   |   __| 
   ___ \    __/  |    | | |   __/  |     |  |   | \__ \ 
 _/    _\ \___| \__| _| |_| \___| _|    _| \__,_| ____/       
                  script creado por Azazel             
"""
print(ascii_art)

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

        self.clear_button = ctk.CTkButton(self.buttons_frame, text="Borrar", command=self.clear_output)
        self.clear_button.grid(row=0, column=7, padx=5, pady=5, sticky="ew")

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
        while not self.queue.empty():
            line = self.queue.get_nowait()
            self.scan_output.insert(ctk.END, line)
            self.scan_output.see(ctk.END)
        self.after(100, self.update_log)

    def log(self, text):
        self.queue.put(text + "\n")

    def clear_output(self):
        self.scan_output.delete("1.0", ctk.END)
        self.log("Reporte borrado.")

    def start_scan(self, scan_type):
        target_url = self.url_entry.get()
        if not target_url:
            self.log("Por favor, ingresa una URL.")
            return

        self.log("-" * 50)
        self.log(f"Iniciando escaneo: {scan_type}")
        self.log("-" * 50)
        self.log("")

        thread = threading.Thread(target=self.run_scan, args=(scan_type, target_url))
        thread.start()

    def run_scan(self, scan_type, target_url):
        parsed_url = urllib.parse.urlparse(target_url)
        hostname = parsed_url.netloc
        
        diccionario_directorios = [
            "admin", "login", "panel", "user", "dashboard", "settings", "config", "backup", "upload", "download",
            "api", "webmail", "phpmyadmin", "cgi-bin", "test", "dev", "stage", "tmp", "logs", "include",
            "lib", "src", "vendor", "public", "private", "protected", "cache", "session", "tmp", "uploads",
            "downloads", "images", "scripts", "styles", "js", "css", "fonts", "robots.txt", "sitemap.xml",
            "crossdomain.xml", "favicon.ico", "wp-admin", "wp-content", "wp-includes", "wp-config.php",
            "wp-login.php", "wp-signup.php", "wp-cron.php", "wp-trackback.php", "wp-comments-post.php",
            "wp-mail.php", "wp-settings.php", "wp-load.php", "wp-blog-header.php", "wp-links-opml.php",
            "wp-atom.php", "wp-rdf.php", "wp-rss.php", "wp-rss2.php", "wp-feed.php", "wp-commentsrss2.php",
            "wp-app.php", "wp-embed.php", "wp-json", "xmlrpc.php", "license.txt", "readme.html"
        ]
        
        if scan_type == "Escaneo Completo":
            self.log("Iniciando escaneo completo...")
            self.log(" ")
            
            self.log("Iniciando escaneo de directorios HTML...")
            get_directories_from_html(target_url, self.log)
            self.log("Escaneo HTML finalizado.")
            self.log(" ")
            
            self.log("Iniciando fuzzing de directorios...")
            fuzz_url(target_url, diccionario_directorios, self.log)
            self.log("Fuzzing finalizado.")
            self.log(" ")
            
            self.log("Iniciando detección de encabezados HTTP...")
            detect_http_headers(target_url, self.log)
            self.log("Detección de encabezados finalizada.")
            self.log(" ")
            
            self.log("Iniciando escaneo con Nmap...")
            run_nmap_scan(hostname, self.log)
            self.log("Escaneo con Nmap finalizado.")
        
        elif scan_type == "HTML":
            get_directories_from_html(target_url, self.log)
        
        elif scan_type == "Fuzzing":
            fuzz_url(target_url, diccionario_directorios, self.log)
        
        elif scan_type == "Headers":
            detect_http_headers(target_url, self.log)
            
        elif scan_type == "Nmap":
            run_nmap_scan(hostname, self.log)
            
        elif scan_type == "OSINT":
            osint_report = security_focused_osint(target_url, self.log)
            if osint_report:
                self.log("\n--- REPORTE DE EXTRACCIÓN OSINT ---")
                for key, value in osint_report.items():
                    self.log(f"\n{key.replace('_', ' ').upper()}:")
                    if isinstance(value, list):
                        if value:
                            for item in value:
                                if isinstance(item, dict):
                                    for form_key, form_value in item.items():
                                        self.log(f"  - {form_key.capitalize()}: {form_value}")
                                else:
                                    self.log(f"  - {item}")
                        else:
                            self.log("  (No se encontraron resultados)")
                    elif isinstance(value, dict):
                        for k, v in value.items():
                            self.log(f"  - {k}: {v}")
                    else:
                        self.log(f"  {value}")

        elif scan_type == "OSINT Avanzado":
            analyze_robots_and_sitemap(target_url, self.log)
            enumerate_subdomains(target_url, self.log)

        self.log("\nAnálisis completado.")


def fuzz_url(target_url, directories, log_func):
    log_func(f"\n--- Iniciando Fuzzing en {target_url} ---")
    for directory in directories:
        url = f"{target_url}/{directory}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                log_func(f"[+] Encontrado: {url} (Código de estado: {response.status_code})")
            elif response.status_code == 403:
                log_func(f"[!] Prohibido: {url} (Código de estado: {response.status_code})")
            elif response.status_code == 404:
                pass
            else:
                log_func(f"[?] Desconocido: {url} (Código de estado: {response.status_code})")
        except requests.exceptions.RequestException as e:
            log_func(f"[!] Error al acceder a {url}: {e}")

def get_directories_from_html(target_url, log_func):
    log_func(f"\n--- Analizando HTML de {target_url} ---")
    try:
        respuesta = requests.get(target_url, timeout=10)
        respuesta.raise_for_status()
        soup = BeautifulSoup(respuesta.text, 'html.parser')

        log_func("\n--- Directorios encontrados en el HTML ---")
        found_links = False
        
        tags_to_check = [('link', 'href'), ('a', 'href'), ('img', 'src'), ('script', 'src')]
        
        for tag_name, attr_name in tags_to_check:
            for tag in soup.find_all(tag_name):
                if tag.has_attr(attr_name):
                    log_func(f"Directorio encontrado: {tag[attr_name]}")
                    found_links = True
        
        if not found_links:
            log_func("No se encontraron directorios en el HTML de la página.")

    except requests.exceptions.RequestException as e:
        log_func(f"Hubo un problema con la conexión: {e}")

def detect_http_headers(target_url, log_func):
    log_func("\n--- Detectando encabezados HTTP ---")
    try:
        respuesta = requests.get(target_url, timeout=10)
        respuesta.raise_for_status()
        for key, value in respuesta.headers.items():
            log_func(f"{key}: {value}")
        
        server_info = respuesta.headers.get('Server', 'No encontrado')
        log_func(f"\nServidor detectado: {server_info}")
    except requests.exceptions.RequestException as e:
        log_func(f"Error de conexión: {e}")

def run_nmap_scan(url, log_func):
    log_func(f"\n--- Iniciando escaneo de Nmap en {url} ---")
    try:
        # Extraer el nombre de host de la URL
        parsed_url = urllib.parse.urlparse(url)
        target = parsed_url.hostname
        
        if not target:
            log_func("Error: No se pudo extraer un nombre de host válido de la URL.")
            return

        command = [
            'nmap', '-sV',
            '--script', 'vuln,http-enum,http-methods,http-waf-detect',
            '--min-rate', '5000',
            target
        ]
        
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                log_func(output.strip())
        
        error_output = process.stderr.read()
        if error_output:
            log_func(f"\n--- Errores de Nmap ---")
            log_func(error_output)

    except FileNotFoundError:
        log_func("Error: Nmap no está instalado o no se encuentra en el PATH del sistema.")
    except Exception as e:
        log_func(f"Error inesperado al ejecutar Nmap: {e}")

def security_focused_osint(url, log_func):
    try:
        response = requests.get(url)
        response.raise_for_status()
        page_content = response.text
        soup = BeautifulSoup(page_content, 'html.parser')

        title = soup.title.string if soup.title else 'Sin título'
        
        forms = []
        for form in soup.find_all('form'):
            form_info = {
                'action': form.get('action', ''),
                'method': form.get('method', '').upper(),
                'inputs': [{'name': input_.get('name', ''),
                            'type': input_.get('type', ''),
                            'placeholder': input_.get('placeholder', '')}
                            for input_ in form.find_all(['input', 'textarea', 'select'])]
            }
            forms.append(form_info)

        technologies = set()
        
        if 'server' in response.headers:
            technologies.add(f"Server: {response.headers['Server']}")
        if 'x-powered-by' in response.headers:
            technologies.add(f"Powered-By: {response.headers['X-Powered-By']}")
        if 'via' in response.headers:
            technologies.add(f"Via: {response.headers['Via']}")
        if 'x-aspnet-version' in response.headers:
            technologies.add(f"ASP.NET: {response.headers['X-AspNet-Version']}")

        scripts = soup.find_all('script')
        for script in scripts:
            if 'src' in script.attrs:
                src = script['src']
                if 'jquery' in src:
                    technologies.add('jQuery')
                elif 'bootstrap' in src:
                    technologies.add('Bootstrap')
                elif 'angular' in src:
                    technologies.add('Angular')
                elif 'react' in src:
                    technologies.add('React')
                elif 'vue' in src:
                    technologies.add('Vue.js')
        links = [a['href'] for a in soup.find_all('a', href=True)]
        for link in links:
            if 'cdn' in link:
                if 'jquery' in link:
                    technologies.add('jQuery')
                elif 'bootstrap' in link:
                    technologies.add('Bootstrap')
                elif 'angular' in link:
                    technologies.add('Angular')
                elif 'react' in link:
                    technologies.add('React')
                elif 'vue' in link:
                    technologies.add('Vue.js')

        external_resources = []
        for tag in ['script', 'link', 'img', 'iframe', 'source']:
            for element in soup.find_all(tag):
                src = element.get('src') or element.get('href')
                if src and (src.startswith('http://') or src.startswith('https://')) and not src.startswith(url):
                     external_resources.append(src)


        potential_vulnerabilities = []
        for form in forms:
            for input_ in form['inputs']:
                if input_['type'] == 'password':
                    potential_vulnerabilities.append(f"Formulario con campo de contraseña en {form['action']}")
        for script in scripts:
            if 'src' in script.attrs and 'cdn' in script['src']:
                potential_vulnerabilities.append(f"Script externo cargado desde {script['src']}")
        for link in external_resources:
            potential_vulnerabilities.append(f"Recurso externo cargado desde {link}")

        sql_injections = re.findall(r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|AND|OR|NOT|LIKE|IN)\b', page_content, re.IGNORECASE)
        if sql_injections:
            potential_vulnerabilities.append("Posibles inyecciones SQL detectadas")

        xss_patterns = [
            r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>',
            r'on\w+\s*=',
            r'<\s*[^>]+?\s*on\w+',
            r'<\s*[^>]+?\s*data\w+',
            r'<\s*[^>]+?\s*expression\(',
            r'<\s*[^>]+?\s*style\s*=\s*[^>]+?expression\(',
            r'<\s*[^>]+?\s*style\s*=\s*[^>]+?url\(',
            r'<\s*[^>]+?\s*href\s*=\s*[^>]+?javascript:',
            r'<\s*[^>]+?\s*src\s*=\s*[^>]+?javascript:'
        ]
        for pattern in xss_patterns:
            if re.search(pattern, page_content, re.IGNORECASE):
                potential_vulnerabilities.append("Posibles vulnerabilidades XSS detectadas")
                break

        email_addresses = re.findall(r'[\w\.-]+@[\w\.-]+', page_content)
        phone_numbers = re.findall(r'\+?\d{1,4}?[\s-]?\(?\d{2,3}\)?[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}', page_content)

        osint_info = {
            'title': title,
            'forms': forms,
            'technologies': list(technologies),
            'potential_vulnerabilities': potential_vulnerabilities,
            'external_resources': external_resources,
            'email_addresses': email_addresses,
            'phone_numbers': phone_numbers
        }

        return osint_info

    except requests.RequestException as e:
        log_func(f"Error al obtener la página: {e}")
        return None

def analyze_robots_and_sitemap(url, log_func):
    log_func("\n--- Análisis de robots.txt ---")
    robots_url = urljoin(url, "/robots.txt")
    try:
        response = requests.get(robots_url, timeout=5)
        if response.status_code == 200:
            log_func("Contenido de robots.txt:")
            disallowed_dirs = re.findall(r"Disallow:\s*(.*)", response.text)
            if disallowed_dirs:
                for path in disallowed_dirs:
                    log_func(f"  - Directorio prohibido: {path.strip()}")
            else:
                log_func("No se encontraron directorios prohibidos.")
        else:
            log_func("No se encontró robots.txt")
    except requests.exceptions.RequestException as e:
        log_func(f"Error al acceder a robots.txt: {e}")

    log_func("\n--- Análisis de sitemap.xml ---")
    sitemap_url = urljoin(url, "/sitemap.xml")
    try:
        response = requests.get(sitemap_url, timeout=5)
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
        log_func(f"Error al acceder a sitemap.xml: {e}")

def check_subdomain(sub, domain, found_subdomains, log_func):
    """Función para ser ejecutada por cada hilo."""
    sub_url = f"https://{sub}.{domain}"
    try:
        response = requests.get(sub_url, timeout=3, allow_redirects=True)
        if response.status_code == 200:
            found_subdomains.append(sub_url)
            log_func(f"  [+] Subdominio encontrado: {sub_url}")
    except requests.exceptions.RequestException:
        pass

def enumerate_subdomains(url, log_func):
    log_func("\n--- Enumeración de subdominios ---")
    domain = urllib.parse.urlparse(url).netloc
    
    subdomains = [
        "www", "blog", "dev", "test", "api", "admin", "mail", "shop", "ftp",
        "webmail", "cpanel", "vpn", "ns1", "ns2", "git", "status", "jira",
        "login", "secure", "static", "images", "cdn", "staging", "beta",
        "proxy", "docs", "portal", "support", "dashboard", "app", "wiki"
    ]
    found_subdomains = []
    
    # Se usa ThreadPoolExecutor para paralelizar el escaneo
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_subdomain, sub, domain, found_subdomains, log_func) for sub in subdomains}
        
    if not found_subdomains:
        log_func("No se encontraron subdominios comunes.")

def run_cli_mode():
    """Ejecuta el programa en modo de terminal."""
    
    print(ascii_art)
    print("Modo de terminal activado. Escribe 'ayuda' para ver las opciones o 'salir' para terminar.")
    
    def cli_log(text):
        print(text)

    diccionario_directorios = [
        "admin", "login", "panel", "user", "dashboard", "settings", "config", "backup", "upload", "download",
        "api", "webmail", "phpmyadmin", "cgi-bin", "test", "dev", "stage", "tmp", "logs", "include",
        "lib", "src", "vendor", "public", "private", "protected", "cache", "session", "tmp", "uploads",
        "downloads", "images", "scripts", "styles", "js", "css", "fonts", "robots.txt", "sitemap.xml",
        "crossdomain.xml", "favicon.ico", "wp-admin", "wp-content", "wp-includes", "wp-config.php",
        "wp-login.php", "wp-signup.php", "wp-cron.php", "wp-trackback.php", "wp-comments-post.php",
        "wp-mail.php", "wp-settings.php", "wp-load.php", "wp-blog-header.php", "wp-links-opml.php",
        "wp-atom.php", "wp-rdf.php", "wp-rss.php", "wp-rss2.php", "wp-feed.php", "wp-commentsrss2.php",
        "wp-app.php", "wp-embed.php", "wp-json", "xmlrpc.php", "license.txt", "readme.html"
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
            print("  osint-avanzado   - Análisis de robots.txt y subdominios.")
        
        elif partes[0] == "analizar":
            if len(partes) < 3:
                print("Error: El comando 'analizar' requiere una opción y una URL.")
                continue
            
            opcion = partes[1]
            url = partes[2]
            
            print(f"\nIniciando escaneo '{opcion}' en {url}...")
            
            if opcion == "completo":
                cli_log("------------------ Analizando Directorios HTML ------------------")
                get_directories_from_html(url, cli_log)
                cli_log("\n------------------ Realizando Fuzzing ------------------")
                fuzz_url(url, diccionario_directorios, cli_log)
                cli_log("\n------------------ Detectando Encabezados HTTP ------------------")
                detect_http_headers(url, cli_log)
                cli_log("\n------------------ Escaneo con Nmap ------------------")
                run_nmap_scan(url, cli_log)
            elif opcion == "html":
                get_directories_from_html(url, cli_log)
            elif opcion == "fuzzing":
                fuzz_url(url, diccionario_directorios, cli_log)
            elif opcion == "headers":
                detect_http_headers(url, cli_log)
            elif opcion == "nmap":
                run_nmap_scan(url, cli_log)
            elif opcion == "osint":
                osint_report = security_focused_osint(url, cli_log)
                if osint_report:
                    cli_log("\n--- REPORTE DE EXTRACCIÓN OSINT ---")
                    for key, value in osint_report.items():
                        cli_log(f"\n{key.replace('_', ' ').upper()}:")
                        if isinstance(value, list):
                            if value:
                                for item in value:
                                    if isinstance(item, dict):
                                        for form_key, form_value in item.items():
                                            cli_log(f"  - {form_key.capitalize()}: {form_value}")
                                    else:
                                        cli_log(f"  - {item}")
                            else:
                                cli_log("  (No se encontraron resultados)")
                        elif isinstance(value, dict):
                             for k, v in value.items():
                                 cli_log(f"  - {k}: {v}")
                        else:
                            cli_log(f"  {value}")
            elif opcion == "osint-avanzado":
                analyze_robots_and_sitemap(url, cli_log)
                enumerate_subdomains(url, cli_log)
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