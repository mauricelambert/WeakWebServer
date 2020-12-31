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

from datetime import datetime
from hmac import new as hmac

class Commons :

	def check_credentials (data, username, password, username_id = "username", password_id = "password") :
		for cred in data :
			if (cred[username_id] == username and 
				hmac(password.encode("utf-16-le"), digestmod = "md4").hexdigest() == cred[password_id]) :
				return True
		return False

	def log (text, base = None, level = 0, save = False, logs_level = 0) :
		if level >= logs_level :
			
			if not level : 
				level = "DEBUG"
			elif level == 1 : 
				level = "INFO"
			elif level == 2 : 
				level = "WARNING"
			elif level == 3 :
				level = "ERROR"
			else :
				level = "CRITICAL"
			
			log_ = f"{datetime.now().strftime('%d/%m/%Y %H:%M:%S')} -> {level} :: {text}"
			
			if save :
				base.add_log(log_)