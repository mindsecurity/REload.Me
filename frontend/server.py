import http.server
import logging
import os
import shutil
from urllib.parse import urlparse
from pathlib import Path

# Configuração de log (nível de debug)
logging.basicConfig(level=logging.DEBUG)

# Caminho onde os arquivos serão armazenados para upload
UPLOAD_DIR = 'uploads'
os.makedirs(UPLOAD_DIR, exist_ok=True)

class MyHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        logging.debug("Request: %s", format % args)

    def do_GET(self):
        """Maneja as requisições GET"""
        logging.info(f"GET Request: {self.path}")
        
        # Exibe a requisição no log
        if self.path == '/upload':
            self.show_upload_form()
        else:
            super().do_GET()

    def do_POST(self):
        """Maneja as requisições POST para upload de arquivos"""
        logging.info(f"POST Request: {self.path}")

        if self.path == '/upload':
            self.handle_file_upload()
        else:
            self.send_error(404, "File Not Found")

    def show_upload_form(self):
        """Exibe um formulário HTML para upload"""
        html_form = """
        <html>
        <body>
            <h2>Upload de Arquivo</h2>
            <form method="POST" enctype="multipart/form-data">
                <input type="file" name="file" />
                <input type="submit" value="Upload" />
            </form>
        </body>
        </html>
        """
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(html_form.encode())

    def handle_file_upload(self):
        """Handle file upload"""
        # Lê a requisição e o tamanho do arquivo
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        # Encontra o nome do arquivo
        filename = self.extract_filename(post_data)
        if filename:
            filepath = os.path.join(UPLOAD_DIR, filename)

            # Salva o arquivo
            with open(filepath, 'wb') as f:
                f.write(post_data)
                
            logging.info(f"Arquivo {filename} enviado com sucesso.")
            
            # Responde ao cliente com o status do upload
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(f"Arquivo {filename} carregado com sucesso!".encode())
        else:
            self.send_error(400, "Bad Request: Não foi possível extrair o nome do arquivo")

    def extract_filename(self, post_data):
        """Extrai o nome do arquivo do formulário POST"""
        try:
            boundary = self.headers['Content-Type'].split('=')[1].encode()
            parts = post_data.split(boundary)
            filename_part = parts[1].split(b'Content-Disposition: form-data; name="file"; filename="')[1]
            filename = filename_part.split(b'"')[0].decode()
            return filename
        except Exception as e:
            logging.error(f"Erro ao extrair nome do arquivo: {e}")
            return None

    def do_DOWNLOAD(self):
        """Maneja o download de arquivos"""
        file_name = self.path.split('/')[-1]
        file_path = os.path.join(UPLOAD_DIR, file_name)

        if os.path.isfile(file_path):
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Disposition', f'attachment; filename={file_name}')
            self.end_headers()
            with open(file_path, 'rb') as f:
                shutil.copyfileobj(f, self.wfile)
            logging.info(f"Arquivo {file_name} baixado com sucesso.")
        else:
            self.send_error(404, "File Not Found")

# Inicia o servidor HTTP
PORT = 3000
Handler = MyHandler
httpd = http.server.HTTPServer(('0.0.0.0', PORT), Handler)

logging.info(f"Servidor iniciado na porta {PORT}. Pressione CTRL+C para parar.")
httpd.serve_forever()

