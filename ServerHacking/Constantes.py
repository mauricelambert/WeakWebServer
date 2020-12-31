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

from enum import Enum
from json import load
from string import ascii_lowercase

file = open("config.json")
config = load(file)
file.close()

class CONSTANTES (Enum) :

	SERVER = config['TCP']["SERVER"]
	PORT = config["TCP"]["PORT"]
	LOGS_LEVEL = config["LOGS"]["LOGS_LEVEL"]
	SAVE_LOGS = config['LOGS']["SAVE_LOGS"]
	BASE_NAME = config['BASES']["NAME"]
	BASE_ADMIN_NAME = config['BASES']["ADMIN_NAME"]
	ALPHABET_RANDOM = ascii_lowercase