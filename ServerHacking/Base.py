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

from sqlite3 import connect
import sqlite3

class Base :
	
	def __init__ (self, file, log) :
		self.file = file
		self.log = log

	def execute (self, request) :
		#self.log("Base.execute", 0)
		cursor, connection = self.execute_request(request)
		cursor.close()
		connection.close()

	def execute_request (self, request) :
		#self.log("Base.execute_request", 0)
		connection = connect(self.file, detect_types = sqlite3.PARSE_DECLTYPES)
		cursor = connection.cursor()
		cursor.execute(request)
		connection.commit()
		return cursor, connection

	def get_login (self, username, password, hash_) :
		self.log("Base.get_login", 0)

		password = hash_(password.encode("utf-16-le"), digestmod = 'md4').hexdigest()
		request = f"""SELECT ID FROM Users WHERE username="{username}" AND password="{password}"; """
		
		cursor, connection = self.execute_request(request)
		id_ = cursor.fetchone()

		id_ = id_[0] if id_ else False
		
		cursor.close()
		connection.close()
		return id_

	def get_logs (self) :
		self.log("Base.get_logs", 0)

		request = "SELECT ID, log, datetime_ FROM Logs;"
		cursor, connection = self.execute_request(request)

		yield from cursor.fetchall()

		cursor.close()
		connection.close()

	def get_messages (self) :
		self.log("Base.get_messages", 0)

		request = "SELECT message, datetime_, username FROM Messages, Users WHERE Users.ID=ID_Users;"
		cursor, connection = self.execute_request(request)
		
		yield from cursor.fetchall()

		cursor.close()
		connection.close()

	def add_log (self, log) :
		#self.log("Base.add_log", 0)
		self.execute(f'INSERT INTO Logs (log) VALUES ("{log}");')

	def add_message (self, message, id_) :
		self.log("Base.add_message", 0)
		self.execute(f"INSERT INTO Messages (message, ID_Users) VALUES ('{message}', '{id_}');")

	def create_table (self, hash_) :
		#self.log("Base.create_table", 2)
		request = """CREATE TABLE IF NOT EXISTS Users ( 
			ID INTEGER PRIMARY KEY AUTOINCREMENT, 
			username CHAR(100) NOT NULL, 
			password CHAR(32) NOT NULL 
		);"""
		self.execute(request)

		request = """CREATE TABLE IF NOT EXISTS 'Logs' ( 
			ID INTEGER PRIMARY KEY AUTOINCREMENT, 
			log TEXT NOT NULL, 
			datetime_ TIMESTAMP DEFAULT CURRENT_TIMESTAMP 
		);"""
		self.execute(request)

		request = """CREATE TABLE IF NOT EXISTS 'Messages' ( 
			ID INTEGER PRIMARY KEY AUTOINCREMENT, 
			message TEXT NOT NULL, 
			datetime_ TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			ID_Users INTEGER,
			FOREIGN KEY(ID_Users) REFERENCES Users(ID)
		);"""
		self.execute(request)

		credentials = { "username" : "password", "user" : "password", "aaa" : "aaa", "H4CKER" : "P4SSWORD", "test" : "PASSW0RD",
			"azerty" : "passw0rd", "qwerty" : "1234", "marjorie" : "a" }
		for username, password in credentials.items() :
			password = hash_(password.encode("utf-16-le"), digestmod = "md4").hexdigest()
			request = "INSERT INTO Users (username, password) VALUES ('{username}', '{password}');".format(
				username = username, password = password)
			self.execute(request)