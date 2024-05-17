import requests
from config import *


class verify:
	def email(email):
		return "@" in email and "." in email and len(email) >= 5

	def password(password, confirm_password):
		return password == confirm_password

def check_new_messages(cipher, token):
	enc_token = cipher.encrypt(token.encode("UTF-8"))
	responce = requests.post(
		server_ip,
		{"token": enc_token.hex(), "update": True},
		verify=False
	)
	return responce.text

def create_dialog(cipher, token):
	recipient = input("Enter recipient`s username\n")
	text = input("Enter text\n")

	token = cipher.encrypt(token.encode("UTF-8"))
	recipient = cipher.encrypt(recipient.encode("UTF-8"))
	text = cipher.encrypt(text.encode("UTF-8"))

	request = requests.post(
		server_ip,
		{"token": token.hex(), "recipient": recipient.hex(), "text": text.hex()},
		verify=False
	)
	return request.text


def auth(cipher, login, password, nickname):
	login = cipher.encrypt(login.encode("UTF-8"))
	password = cipher.encrypt(password.encode("UTF-8"))
	nickname = cipher.encrypt(nickname.encode("UTF-8"))

	responce = requests.post(
		server_ip,
		{"login": login.hex(), "password": password.hex(), "nickname": nickname.hex()},
		verify=False
	)
	return responce.text


def start(cipher):
	action = input("Login or register? (l/r)\n")
	if action.lower() == "l":
		email = input("Enter login\n")
		if verify.email(email):
			password = input("Enter password\n")

			responce = auth(cipher, email, password, "None")
			if len(responce) > 60:
				TOKEN = responce
				print(repr(TOKEN))
				print(check_new_messages(cipher, TOKEN))
				print(create_dialog(cipher, TOKEN))
			else:
				print(responce)
				return start(cipher)
		else:
			print("Enter the correct login")
			return start(cipher)

	elif action.lower() == "r":
		username = input("Enter your nickname\n")
		email = input("Enter your email for login\n")
		if verify.email(email):
			password = input("Enter the password\n")
			confirm_password = input("Confirm your password\n")
			if verify.password(password, confirm_password):
				responce = auth(cipher, email, password, username)
				if len(responce) > 60:
					print(responce)
					return start(cipher)
				else:	
					print(responce)
					return start(cipher)
			else:
				print("Passwords don't match")
				return start(cipher)
		else:
			print("Enter the correct email")
			return start(cipher)
	else:
		print("Enter a valid query")
		return start(cipher)
