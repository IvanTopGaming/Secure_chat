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

import sqlite3
import uuid
import rsa
import jwt

from builtins import print as p
from datetime import datetime
from Crypto.Cipher import AES
from flask import Flask, request, render_template
from flask_restful import Api, Resource

users = sqlite3.connect("users.db", autocommit=True, check_same_thread=False)
messages = sqlite3.connect("messages.db", autocommit=True, check_same_thread=False)
u_cursor = users.cursor()
m_cursor = messages.cursor()

u_cursor.execute(
	"""
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER,
		username TEXT,
		email TEXT,
		password TEXT
	)
"""
)

m_cursor.execute(
	"""
	CREATE TABLE IF NOT EXISTS messages (
		message_id TEXT,
		message_time TEXT,
		is_read BOOL,
		dialog_id TEXT,
		sender_id TEXT,
		recipient_id TEXT,
		message_text TEXT
	)
"""
)
m_cursor.execute(
	"""
	CREATE TABLE IF NOT EXISTS dialogs (
		dialog_id TEXT,
		dialog_one_user_id TEXT,
		dialog_two_user_id TEXT
	)
"""
)

jwt_key_token = AES.get_random_bytes(32)  # We need to update it once in 30 mins
(pubkey, privkey) = rsa.newkeys(1024)

app = Flask(__name__)
api = Api(app)


def secure_pipe(crypto_str):
	crypto = bytes.fromhex(crypto_str)
	message = rsa.decrypt(crypto, privkey)

	key = message.split(b"  ")[0]
	nonce = message.split(b"  ")[1]

	cipher = AES.new(key, AES.MODE_EAX, nonce)
	return cipher


def has_dialog(recipient_id, sender_id):
	m_cursor.execute(
		"""SELECT * FROM dialogs WHERE (dialog_one_user_id AND dialog_two_user_id) = ((?) OR (?))""",
		(
			recipient_id,
			sender_id,
		),
	)
	data = m_cursor.fetchall()
	if data == []:
		return False
	else:
		return data[0][0]


def get_username(ID):
	u_cursor.execute("""SELECT * FROM users WHERE id = (?)""", (ID,))
	data = u_cursor.fetchall()

	if data == []:
		return None
	else:
		return data[0][1]


def get_id(username):
	u_cursor.execute("""SELECT * FROM users WHERE username = (?)""", (username,))
	data = u_cursor.fetchall()

	if data == []:
		return None
	else:
		return data[0][0]


def get_token(email, password, nickname):
	token = jwt.encode(
		{"email": email, "password": password, "nickname": nickname},
		jwt_key_token,
		algorithm="HS256",
	)
	return token


def register(nickname, email, password):
	u_cursor.execute(
		f"""SELECT * FROM users WHERE email = (?) OR username = (?)""",
		(
			email,
			nickname,
		),
	)
	if u_cursor.fetchall() == []:
		u_cursor.execute(
			"""INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)""",
			(
				str(uuid.uuid4()),
				nickname,
				email,
				password,
			),
		)
		users.commit()
		# token = get_token(email, password, nickname)
		# request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
		return "SUCCESS"
	else:
		return "USER WITH SUCH EMAIL OR USERNAME ALREADY REGISTRED"


def login(email, password):
	email = email.lower()
	u_cursor.execute(f"""SELECT * FROM users WHERE email = (?)""", (email,))
	data = u_cursor.fetchall()

	if data != []:
		if data[0][3] == password:
			nickname = data[0][1]
			token = get_token(email, password, nickname)
			return token
		else:
			return "PASSWORD IS INCORRECT"
	else:
		return "USER NOT FOUND"


@app.route("/")
def home():
	return render_template("index.html")


class API(Resource):
	def get(self):
		# return 'Hello ' + request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr), 200 # Ok
		return pubkey.save_pkcs1().decode("UTF-8")

	def post(self):
		data = request.form
		crypto_str = data.get("secure_pipe")
		nickname, email, password = (
			data.get("nickname"),
			data.get("login"),
			data.get("password"),
		)
		token = data.get("token")
		recipient, text = data.get("recipient"), data.get("text")
		update = data.get("update")

		if crypto_str != None:
			global cipher
			cipher = secure_pipe(crypto_str)

		if email != None:
			email = cipher.decrypt(bytes.fromhex(email)).decode("UTF-8")
			password = cipher.decrypt(bytes.fromhex(password)).decode("UTF-8")
			nickname = cipher.decrypt(bytes.fromhex(nickname)).decode("UTF-8")

			if nickname == "None":
				return login(email, password)
			else:
				return register(nickname, email, password)

		if token != None:
			token = (
				cipher.decrypt(bytes.fromhex(token))
				.decode("UTF-8")
				.replace('"', "")
				.replace("\n", "")
			)

			try:
				sender = jwt.decode(token, jwt_key_token, algorithms="HS256")
			except jwt.exceptions.InvalidSignatureError:
				return "INVALID TOKEN"

			sender_id = get_id(sender["nickname"])

			if update == "True":
				m_cursor.execute(
					f"""SELECT * FROM messages WHERE is_read = (?) AND sender_id = (?)""",
					(False, sender_id),
				)
				data = m_cursor.fetchall()

				if data == []:
					return "No unread messages"
				else:
					m_cursor.execute(
						"""UPDATE messages SET is_read = (?) WHERE sender_id = (?)""",
						(True, sender_id),
					)
					patchrd_data = []

					for i in range(len(data)):
						patchrd_data.append(
							{
								"ID": data[i][0],
								"Time": data[i][1],
								"To": get_username(data[i][4]),
								"From": get_username(data[i][5]),	
								"Text": data[i][6],
							}
						)
					return patchrd_data

			if (recipient or text) != None:
				recipient = cipher.decrypt(bytes.fromhex(recipient)).decode("UTF-8")
				text = cipher.decrypt(bytes.fromhex(text)).decode("UTF-8")

				recipient_id = get_id(recipient)

				if recipient_id == None:
					return "USER NOT FOUND"
				else:
					dialog_id = has_dialog(recipient_id, sender_id)
					# if not dialog_id:
					# 	m_cursor.execute(
					# 		"""INSERT INTO dialogs (dialog_id, dialog_one_user_id, dialog_two_user_id) VALUES (?, ?, ?)""",
					# 		(
					# 			str(uuid.uuid4()),
					# 			recipient_id,
					# 			sender_id
					# 		),
					# 	)

					m_cursor.execute(
						"""INSERT INTO messages (message_id, message_time, is_read, dialog_id, sender_id, recipient_id, message_text) VALUES (?, ?, ?, ?, ?, ?, ?)""",
						(
							str(uuid.uuid4()),
							str(datetime.now()),
							False,
							dialog_id,
							recipient_id,
							sender_id,
							text,
						),
					)

		return "Done"


api.add_resource(API, "/api")

if __name__ == "__main__":
	app.run(host='0.0.0.0', port=5000)
