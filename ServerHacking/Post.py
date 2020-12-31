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

class Post :

	def process_post (request, log, authentication) :
		log_("Post.process_post", 0)
		body = Post.get_body(request)
		function = Post.find_path(request)
		return function(request, body, log)

	def find_path (request) :
		log_("Post.find_path", 0)
		if request.path == "/login" :
			return Post.login

	def get_body (request, log) :
		log_("Post.get_body", 0)
		try :
			content_length = int(self.headers['Content-Length'])
			body = self.rfile.read(content_length).decode()
		except Exception as e :
			log(f"HTTP error : can't read body...", 4)
			body = ""

		return body

	def login (request) :
		log("Post.request", 0)
		