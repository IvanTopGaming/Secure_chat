logo = """
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░▓▒░░░░░▒▓▓░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░████▓▒▓████▒░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░▓████████████░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░█████████████▒░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░▓██████████████░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░███████████████▒░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░▒▓▓▓▓███████▓▓▓▒░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░▒▒▓▓██▓▓▓▒▒▒▒▒▒▒▒▒▒▓▓▓██▓▓▓▒▒░░░░░░░░░░░
░░░░░▒▓███████████████████████████████████▓░░░░░░░
░░░░░▓████████████████████████████████████▓▒░░░░░░
░░░░░░░░░▒▒▓▓▓▓██████████████████▓▓▓▓▒▒░░░░░░░░░░░
░░░░░░░░░▓███▓░░▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓░░▒████▓▒░░░░░░░░░
░░░░░░▒▓███████░▓█████▓░░▒█████▓░░▓███████▓▒░░░░░░
░░░░▒███████████░░░▒░░░░░░░░▒░░░░▓███████████▒░░░░
░░░░░░░░░▒▒▓▓████▒░░░░░░░░░░░░▒██████▓▓▒▒░░░░░░░░░
░░░░░░░░░░░░░▒█████░░░░░░░░░▒██████▒░░░░░░░░░░░░░░
░░░░░░░░░░░▒████████▓░░░░░░▓████████▓▓░░░░░░░░░░░░
░░░░░░░░░░░░░▒▒▓██████▓▒░░██████▓▒░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░▒▓████░████▒░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░▒▒▓██▒░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░█▒░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░▒░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
"""

import requests
import sys
from builtins import print as p
from sys import platform

from connect import connect
from start import start


def errors(func):
	def wrapper(*args, **kwargs):
		try:
			func(*args, **kwargs)
		except Exception as e:
			print(f"Error {e}")
			action = input("Exit? (y/n)\n")
			if action.lower() == "y":
				sys.exit(e)

	return wrapper


# @errors
def main():
	if platform == "linux" or platform == "linux2":
		sys.exit("This OS does not suppurterd yet")
	elif platform == "darwin":
		sys.exit("This OS does not suppurted")
	elif platform == "win32":
		try:
			key = connect()
			start(key)
		except requests.exceptions.ConnectionError:
			sys.exit("The server is not responding")
	else:
		sys.exit("This OS does not suppurted")


if __name__ == "__main__":
	main()
# os.system("echo hello")
