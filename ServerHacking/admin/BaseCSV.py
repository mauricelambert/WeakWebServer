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

from csv import reader, writer

class BaseCSV :

	def __init__ (self, filename) :
		self.filename = filename

	def read (self) :
		with open(self.filename, newline = "") as csvfile :
			data = list(reader(csvfile, delimiter = ","))
		return data
			
	def change_value (self, value, column, value_where_change) :
		data = self.read()
		with open(self.filename, "w", newline = "") as csvfile :
			writer_ = writer(csvfile)
			for line in data :
				if value_where_change in line :
					line[column] = value
				writer_.writerow(line)
