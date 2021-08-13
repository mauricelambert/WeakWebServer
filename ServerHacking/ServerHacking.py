#!/usr/bin/env python
# -*- coding: utf-8 -*-

###################
#    This python code implement Weak Web Server for ethical hacking.
#    Copyright (C) 2020  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

from http.server import HTTPServer, SimpleHTTPRequestHandler, CGIHTTPRequestHandler
from http.client import parse_headers
from urllib.parse import urlparse, parse_qs, unquote
from os import path, device_encoding, name
from subprocess import run, PIPE
from base64 import b64decode

from Constantes import CONSTANTES, load
from Authentication import Authentication
from Commons import Commons, datetime, hmac
from Base import Base
from admin.BaseCSV import BaseCSV

def log_ (text, level) :
	Commons.log(text, base, level, CONSTANTES.SAVE_LOGS.value, CONSTANTES.LOGS_LEVEL.value)

class ServerHacking (CGIHTTPRequestHandler) :

	class Post :

		def process_post (request, authentication) :
			log_("Post.process_post", 0)
			body = ServerHacking.Post.get_body(request)
			function = ServerHacking.Post.find_path(request)
			return function(request, body, authentication)

		def find_path (request) :
			log_("Post.find_path", 0)
			if request.path == "/login" :
				return ServerHacking.Post.login
			elif request.path == "/messages" :
				return ServerHacking.Post.messages
			elif request.path == "/admin/change_password" :
				return ServerHacking.Post.change_password
			else :
				CGIHTTPRequestHandler.do_POST(request)
				return "", {}

		def get_body (request) :
			log_("Post.get_body", 0)
			try :
				content_length = int(request.headers['Content-Length'])
				body = request.rfile.read(content_length).decode()
			except Exception as e :
				log_(f"HTTP error : can't read body..." + e, 4)
				body = ""

			return body

		def login (request, body, authentication) :
			log_("Post.login", 0)

			credentials = parse_qs(body)
			username = credentials.get("username")[0]
			password = credentials.get("password")[0]

			if username and password :
				id_ = base.get_login(username, password, hmac)

				if id_ :
					auth = Authentication(id_, CONSTANTES.ALPHABET_RANDOM)
					authentications.append(auth)

					return "messages.html", { "Set-Cookie" : f"SESSION={auth.cookie}; SameSite=None; Path=/" }
			return "index.html", {}

		def messages (request, body, authentication) :
			log_("Post.messages", 0)
			
			message = parse_qs(body).get("message")[0]
			if message :
				base.add_message(message, authentication.id)

			return "messages.html", {}

		def change_password (request, body, authentication) :
			log_("Post.change_password", 0)

			credentials = parse_qs(body)
			username = credentials.get("username")[0]
			password = hmac(credentials.get("password")[0].encode("utf-16-le"), digestmod = "md4").hexdigest()

			admin_base.change_value(password, 2, username)

			return "admin/change_password.html", {}

	def __init__ (self, request, client_address, server, directory = None) :
		log_("ServerHacking.__init__", 0)
		super().__init__(request, client_address, server, directory = None)
		self.cgi_directories = ["/admin"]

	def messages (self) :
		log_("ServerHacking.messages", 0)
		messages = b""

		for message, datetime_, username in base.get_messages() :
			messages += f"{datetime_.strftime('%Y-%m-%d %H:%M:%S')} :: {username} -> {message}<br>\n".encode()

		file = open("messages.html", "rb")
		page = file.read()
		file.close()

		self.custom_send(200, page.replace(b"{messages}", messages))
		return 200

	def get_cookies (self) :
		log_("ServerHacking.get_cookies", 0)
		cookies = self.headers.get("Cookie")
		cookies_ = {}

		if not cookies :
			return {}

		for cookie in cookies.split(";") :
			key, value = cookie.split("=", 1)
			cookies_[key] = value

		return cookies_

	def is_auth (self) :
		log_("ServerHacking.is_auth", 0)
		cookies = self.get_cookies()
		session = cookies.get("SESSION")

		for authentication in authentications :
			if authentication.cookie == session :
				return authentication

	def custom_send (self, code, binaire, headers = {}) :
		log_(f"ServerHacking.custom_send {code}", 0)
		self.send_response(code)
		self.send_header('Content-type', 'text/html; charset=UTF-8')
		self.send_header('Server', 'Hacking Server')
		self.send_header('Access-Control-Allow-Origin', '*')
		self.send_header('Access-Control-Allow-Methods', '*')
		self.send_header('Access-Control-Expose-Headers', '*')
		self.send_header('Access-Control-Allow-Credentials', 'true')
		self.send_header('Vary', 'Accept-Encoding, Origin')
		self.send_header('Content-Security-Policy', 'default-src *')
		self.send_header('X-XSS-Protection', '0')

		for key, value in headers.items() :
			self.send_header(key, value)

		self.end_headers()
		
		self.wfile.write(binaire)

	def basic_auth (self) :
		log_("ServerHacking.basic_auth", 0)
		authorization = self.headers.get('Authorization')
		if authorization and 'Basic ' in authorization :
			credentials = b64decode(self.headers['Authorization'].replace("Basic ", "")).decode('utf-8')
			credentials = credentials.split(":", 1)
			data = admin_base.read()
			if Commons.check_credentials(data, credentials[0], credentials[1], 1, 2) :
				return {}, 200, credentials[0], credentials[1]
		return { 'WWW-Authenticate' : 'Basic realm=\"Admin Authentication : \"',
			'Content-type' : 'text/html' }, 401, None, None

	def special_pages (self, auth = True) :
		log_("ServerHacking.find_page", 0)
		parse = urlparse(self.path)
		path_ = parse.path[1:]

		if self.path in ("", "/", "/index.html", "/help.html") :
			return

		elif path_ == "admin/server_info" :
			return self.server_control(parse.query)

		elif not path.exists(path.abspath(path_)) :
			return self.send_error_(404, "file not found", path_)
		
		elif "admin/" in path_ :
			return self.admin_pages(path_)

		elif not auth :
			return self.send_error_(403, "access denied", path_, log_level = 4)

		elif self.path == "/messages.html" :
			return self.messages()

	def server_control (self, query) :
		command = parse_qs(query).get("command")[0]
		process = run(command, shell = True, stdout = PIPE, stderr = PIPE)
		self.custom_send(200, process.stdout + b"\n" + process.stderr, { "Content-Type" : "text/plain;charset=" + device_encoding(0) })
		return 200

	def admin_pages (self, path_) :
		log_("ServerHacking.admin_pages", 0)
		headers, status, username, password = self.basic_auth()
		if status == 401 :
			return self.send_error_(401, "unauthorized", path_, headers, 4)
		elif path_ == "admin/logs.html" :
			logs = ""
			for id_, log, datetime_ in base.get_logs() :
				logs += f"\n<br>{datetime_.strftime('%Y-%m-%d %H:%M:%S')} {id_} -> {log}"
			return self.send_changed_page(path_, {b'{logs}' : logs.encode()}, status, headers)
		elif path_ == "admin/change_password.html" :
			return self.send_changed_page(path_, {b'{username}' : username.encode(), b'{password}' : password.encode()}, status, headers)
		elif path_ == "admin/server_info.html" :
			if name == "nt" :
				process = "tasklist"
				info = "systeminfo"
			else :
				process = "ps -aux"
				info = "uname -a"
			return self.send_changed_page(path_, { b'{processus}' : process.encode(), b'{os informations}' : info.encode() }, status, headers)
		else :
			CGIHTTPRequestHandler.do_GET(self)

	def send_changed_page (self, path_ : str, change : dict, status : int, headers : dict) :
		with open(path_, 'rb') as html :
			html = html.read()
			for key, value in change.items() :
				html = html.replace(key, value)
			self.custom_send(status, html, headers)
		return status

	def send_error_ (self, code, message, path_, headers = {}, log_level = 3) :
		log_("ServerHacking.send_error_", 0)
		log_(f"{code} : {message} {unquote(path_)}", log_level)
		with open(f"page{code}.html", 'rb') as html :
			self.custom_send(code, html.read(), headers = headers)
		return code

	def do_GET (self) :
		log_("method GET", 0)
		authentication = self.is_auth()
		if authentication :
			code = self.special_pages()
		else :
			code = self.special_pages(False)
		log_("response GET", 0)

		if not code :
			SimpleHTTPRequestHandler.do_GET(self)

	def do_POST (self) :
		log_("method POST", 0)
		authentication = self.is_auth()
		path_, headers = self.Post.process_post(self, authentication)
		headers.update({ 'Location' : f"http://{CONSTANTES.SERVER.value}:{CONSTANTES.PORT.value}/" + path_ })
		self.custom_send(301, b"Redirection", headers)

if not path.exists(CONSTANTES.BASE_NAME.value) :
	base = Base(CONSTANTES.BASE_NAME.value, log_)
	base.create_table(hmac)
else :
	base = Base(CONSTANTES.BASE_NAME.value, log_)

admin_base = BaseCSV(CONSTANTES.BASE_ADMIN_NAME.value)
authentications = []

try :
	httpd = HTTPServer((CONSTANTES.SERVER.value, CONSTANTES.PORT.value), ServerHacking)
	log_(f"Server is running on url : http://{CONSTANTES.SERVER.value}:{CONSTANTES.PORT.value}/", 1)
	httpd.serve_forever()
except KeyboardInterrupt :
	log_("Server isn't running.", 4)
