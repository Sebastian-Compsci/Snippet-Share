import sqlite3
import os
import json
from flask import Flask, request, jsonify

import hashlib
import base64
import hmac

app = Flask(__name__)
db_name = "snippets.db"
sql_file = "snippets.sql"
db_flag = False

def jwt_generator(username):
	with open("key.txt", "r") as file:
		key = file.read().strip().encode('utf-8')

	header = {"alg": "HS256","typ": "JWT"}
	headerjson = json.dumps(header).encode('utf-8')
	header_b64 = base64.urlsafe_b64encode(headerjson).decode('utf-8')

	payload = {"username": username}
	payloadjson = json.dumps(payload).encode('utf-8')
	payload_b64 = base64.urlsafe_b64encode(payloadjson).decode('utf-8')

	signature = f"{header_b64}.{payload_b64}".encode('utf-8')
	signaturehmac = hmac.new(key, signature, hashlib.sha256).hexdigest()

	jwt = f"{header_b64}.{payload_b64}.{signaturehmac}"
	return jwt

def jwt_decode(jwt):
	with open("key.txt", "r") as file:
		key = file.read().strip().encode('utf-8')
	try:
		header_b64, payload_b64,signature = jwt.split('.')
	except ValueError:
		return None

	sig_check = f"{header_b64}.{payload_b64}".encode('utf-8')
	expected = hmac.new(key, sig_check, hashlib.sha256).hexdigest()
	if expected != signature:
		return None
	payload_json = base64.urlsafe_b64decode(payload_b64.encode('utf-8'))
	payload = json.loads(payload_json.decode('utf-8'))
	return payload.get("username")

def create_db():
    conn = sqlite3.connect(db_name)
    
    with open(sql_file, 'r') as sql_startup:
    	init_db = sql_startup.read()
    cursor = conn.cursor()
    cursor.executescript(init_db)
    conn.commit()
    conn.close()
    global db_flag
    db_flag = True
    return conn

def get_db():
	if not db_flag:
		create_db()
	conn = sqlite3.connect(db_name)
	conn.execute("PRAGMA foreign_keys = ON;")
	return conn



@app.route('/', methods=(['GET']))
def index():
	conn = get_db()
	cursor = conn.cursor()
	cursor.execute("SELECT first_name FROM users LIMIT 10")
	result = cursor.fetchall()
	conn.close()

	return result


@app.route('/clear', methods=(['GET']))
def clear():
	global db_flag
	db_flag = False
	try:
		conn = sqlite3.connect(db_name)

	finally:
		conn.close()
	try:
		if os.path.exists(db_name):
			os.remove(db_name)
	except PermissionError as e:
		# print(f"Couldnt delete db")
		pass

	create_db()
	return jsonify({'status': 'success'})

@app.route('/create_user', methods=["GET", "POST"])
def create_user():
	if request.method == 'POST':
		first_name = request.form['first_name']
		last_name = request.form['last_name']
		username = request.form['username']
		email = request.form['email_address']
		password = request.form['password']
		salt = request.form['salt']
		db = get_db()

		error = None

		hash = hashlib.sha256()
		passbyte = password.encode('utf-8')
		hash.update(passbyte)
		saltbyte = salt.encode('utf-8')
		hash.update(saltbyte)

		jwt = jwt_generator(username)

		cur = db.cursor()
		cur.execute("SELECT email_address FROM users WHERE email_address = ?", (email,))
		result = cur.fetchone()
		if result:
			db.close()
			return jsonify({"status": 3, "pass_hash": "NULL"})

		cur = db.cursor()
		cur.execute("SELECT username FROM users WHERE username = ?", (username,))
		result = cur.fetchone()
		if result:
			db.close()
			return jsonify({"status": 2, "pass_hash": "NULL"})


		lower = False
		upper = False
		number = False
		for char in password:
			ascii = ord(char)
			if 90 >= ascii >= 65:
				upper = True
			if 122 >= ascii >= 97:
				lower = True
			if 57 >= ascii >= 48:
				number = True

		if (len(password) < 8 or not lower or not upper or not number or username in password or
				first_name in password or last_name in password):
			db.close()
			return jsonify({"status": 4, "pass_hash": "NULL"})

		if error is None:
			try:
				db.execute(
					"INSERT INTO users (first_name, last_name, username, email_address, passhash, salt) VALUES (?, ?, ?, ?, ?, ?)",
					(first_name, last_name, username, email, hash.hexdigest(), salt))
				db.execute("INSERT INTO old_hashes (username, passhash) VALUES (?, ?)", (username, hash.hexdigest()), )
				db.commit()
				db.close()
			except sqlite3.IntegrityError:
				error = f"User {username} already exists"
		db.close()
		return jsonify({"status": 1, "pass_hash": hash.hexdigest()})

	return """
	<h1>Create User</h1>
	<form action="" method="post" novalidate>

		<p>
			First Name: <br>
			<input type = "text" name = "first_name" size = "32">
		</p>
		<p>
			Last Name: <br>
			<input type = "text" name = "last_name" size = "32">
		</p>
		<p>
			Username: <br>
			<input type = "text" name = "username" size = "32">
		</p>
		<p>
			Email: <br>
			<input type = "text" name = "email_address" size = "32">
		</p>
		<p>
			Password: <br>
			<input type = "text" name = "password" size = "32">
		</p>
		<p>
			Salt: <br>
			<input type = "text" name = "salt" size = "32">
		</p>
		<p>
			<input type="submit" value="Create User">
		</p>

	</form>

	"""


@app.route('/login', methods=["GET", "POST"])
def login():
	if request.method == 'POST':
		username = request.form['username']
		password = request.form['password']
		db = get_db()

		cur = db.cursor()
		cur.execute("SELECT salt FROM users WHERE username = ?", (username,))
		salt = cur.fetchone()

		if salt is None:
			return jsonify({"status": 3, "jwt": "NULL"})

		salt = str(salt[0])
		hash = hashlib.sha256()
		passbyte = password.encode('utf-8')
		hash.update(passbyte)
		saltbyte = salt.encode('utf-8')
		hash.update(saltbyte)

		cur = db.cursor()
		cur.execute("SELECT passhash FROM users WHERE username = ?", (username,))
		result = cur.fetchone()
		if result and result[0] == hash.hexdigest():
			jwt = jwt_generator(username)
			db.close()
			return jsonify({"status": 1, "jwt": jwt})
		db.close()
		return jsonify({"status": 2, "jwt": "NULL"})

	return """
		<h1>Login</h1>
		<form action="" method="post" novalidate>

			<p>
				Username: <br>
				<input type = "text" name = "username" size = "32">
			</p>
			<p>
				Password: <br>
				<input type = "password" name = "password" size = "32">
			</p>
			<p>
				<input type="submit" value="Login">
			</p>

		</form>

		"""


order = 1
#order used so most recent recipies can be found
@app.route('/create_snippet', methods=["GET", "POST"])
def create_snippet():
	global order
	if request.method == "POST":
		jwt_auth = request.headers.get('Authorization')
		if not jwt_auth:
			return jsonify({"status": 2})
		db = get_db()


		username = jwt_decode(jwt_auth)
		if not username:
			return jsonify({"status": 2})

		snippet_name = request.form.get('name')
		description = request.form.get('description')
		snippet_id = request.form.get('snippet_id')
		code = request.form.get('code')

		try:
			db = get_db()
			cur = db.cursor()
			cur.execute("INSERT INTO snippets (title, description, code, username, orderID) VALUES (?,?,?,?,?)",
						(snippet_name, description, code, username, order))
			order += 1
			db.commit()
			db.close()
			return jsonify({"status": 1, "snippet_id": order-1})
		except Exception:
			db.close()
			return jsonify({"status": 2})


	return """
		<h1>Create Recipe</h1>
		<form action="" method="post" novalidate>

			<p>
				Recipe Name: <br>
				<input type = "text" name = "name" size = "32">
			</p>
			<p>
				Description: <br>
				<input type = "text" name = "description" size = "32">
			</p>
			<p>
				Snippet ID: <br>
				<input type = "integer" name = "snippet_id" size = "32">
			</p>
			<p>
				Code: <br>
				<input type = "text" name = "code" size = "32">
			</p>
			<p>
				<input type="submit" value="Create Recipe">
			</p>

		</form>

		"""

@app.route('/like', methods=["GET", "POST"])
def like():
	if request.method == "POST":
		#ensure user login
		jwt_auth = request.headers.get('Authorization')
		if not jwt_auth:
			return jsonify({"status": 2})
		db = get_db()


		username = jwt_decode(jwt_auth)
		if not username:
			return jsonify({"status": 2})

		snippet_id = request.form.get("snippet_id")
		if not snippet_id:
			return jsonify({"status": 3})
		cur = db.cursor()
		cur.execute("SELECT * FROM snippets WHERE orderID=?", (snippet_id,))
		row = cur.fetchone()
		if not row:
			db.close()
			return jsonify({"status": 2})
		try:
			db = get_db()
			cur = db.cursor()
			cur.execute("INSERT INTO likes (username, snippet_id) VALUES (?, ?)", (username, snippet_id))
			db.commit()
			db.close()
			return jsonify({"status": 1})
		except Exception:
			db.close()
			return jsonify({"status": 2})



	return """
			<h1>Like Snippet</h1>
			<form action="" method="post" novalidate>
				<p>
					Snippet ID: <br>
					<input type = "integer" name = "snippet_id" size = "32">
				</p>
				<p>
					<input type="submit" value="Like">
				</p>
			</form>

			"""

@app.route('/view_recipe/<recipe_id>', methods=(['GET', 'POST']))
def view_recipe(snippet_id):
	if request.method == 'GET':
		jwt_auth = request.headers.get('Authorization')
		if not jwt_auth:
			return jsonify({"status": 2, "data": "NULL"})
		db = get_db()

		nameBool = request.args.get("name") == "True"
		descBool = request.args.get("description") == "True"
		likesBool = request.args.get("likes") == "True"
		codeBool = request.args.get("code") == "True"

		toreturn = {}

		cur = db.cursor()
		cur.execute("SELECT title, description, code FROM snippets WHERE orderID=?", (snippet_id,))
		row = cur.fetchone()
		if not row:
			db.close()
			return jsonify({"status": 2, "data": "NULL"})

		if nameBool:
			toreturn["name"] = row[0]
		if descBool:
			toreturn["description"] = row[1]
		if codeBool:
			toreturn["code"] = row[2] if row[2] else ""
		if likesBool:
			cur = db.cursor()
			cur.execute("SELECT COUNT(*) FROM likes WHERE snippet_id=?", (snippet_id, ))
			count = cur.fetchone()[0]
			toreturn["likes"] = str(count)
		db.close()
		return jsonify({"status": 1, "data": toreturn})

	return """
			<h1>View Snippet</h1>
			<form action="" method="post" novalidate>
				<p>
					Write "True" in any box for data you want to retrieve.
				</p>
				<p>
					Title: <br>
					<input type = "boolean" name = "name" size = "32">
				</p>
				<p>
					Description: <br>
					<input type = "boolean" name = "description" size = "32">
				</p>
				<p>
					Likes: <br>
					<input type = "boolean" name = "likes" size = "32">
				</p>
				<p>
					Code: <br>
					<input type = "boolean" name = "code" size = "32">
				</p>
				<p>
					<input type="submit" value="View">
				</p>
			</form>

			"""

@app.route('/delete_user', methods=["GET", "POST"])
def delete_user():
	if request.method == 'POST':
		jwt_auth = request.headers.get('Authorization')
		if not jwt_auth:
			return jsonify({"status": 2})

		db = get_db()

		username_form = request.form["username"]

		username = jwt_decode(jwt_auth)
		if not username or username != username_form:
			return jsonify({"status": 2})

		cur = db.cursor()
		cur.execute("DELETE FROM users WHERE username = ?", (username,))
		db.commit()
		db.close()
		return jsonify({"status": 1})



	return """
		<h1>Delete User</h1>
		<form action="" method="post" novalidate>
			<p>
				Username: <br>
				<input type = "text" name = "username" size = "32">
			</p>
			<p>
				<input type="submit" value="Delete">
			</p>
		</form>

		"""

@app.route('/follow', methods=["GET", "POST"])
def follow():
	if request.method == 'POST':
		jwt_auth = request.headers['Authorization']
		if not jwt_auth:
			return jsonify({"status": 2})

		db = get_db()

		username_to_follow = request.form.get("username")
		if not username_to_follow:
			return jsonify({"status":3})

		follower = jwt_decode(jwt_auth)
		if not follower:
			return jsonify({"status": 2})

		if username_to_follow == follower:
			return jsonify({"status":4})

		cur = db.cursor()
		cur.execute("SELECT username FROM users WHERE username=?", (username_to_follow,))
		row = cur.fetchone()
		if row is None:
			db.close()
			return jsonify({"status": 5})




		cur = db.cursor()
		cur.execute("SELECT * FROM following WHERE follower=? AND following=?", (follower, username_to_follow))
		if cur.fetchone() is not None:
			db.close()
			return jsonify({"status": 1})
		try:
			cur = db.cursor()
			cur.execute("INSERT INTO following(follower, following) VALUES (?, ?)", (follower, username_to_follow))
			db.commit()
			db.close()
			return jsonify({"status": 1})
		except Exception:
			db.close()
			return jsonify({"status": 2})

	return """
		<h1>Follow User</h1>
		<form action="" method="post" novalidate>
			<p>
				Username: <br>
				<input type = "text" name = "username" size = "32">
			</p>
			<p>
				<input type="submit" value="Like">
			</p>
		</form>

		"""

@app.route('/search', methods=["GET", "POST"])
def search():
	if request.method == 'GET':
		jwt_auth = request.headers.get('Authorization')
		if not jwt_auth:
			return jsonify({"status": 2, "data": "NULL"})

		db = get_db()

		username = jwt_decode(jwt_auth)
		if not username:
			return jsonify({"status": 2, "data": "NULL"})

		feedBool = request.args.get("feed") == "True"
		popularBool = request.args.get("popular") == "True"
		query = request.args.get("query")

		data = {}
		if feedBool:
			cur = db.cursor()
			cur.execute("SELECT * FROM recipes WHERE username IN (SELECT following FROM following WHERE follower=?) ORDER BY orderID DESC LIMIT 2", (username, ))
			snippets = cur.fetchall()

			for snippet in snippets:
				snippet_id = snippet[4]
				recipeId = snippet[0]
				desc = snippet[1]
				code = json.loads(snippet[2])
				username = snippet[3]
				cur = db.cursor()
				cur.execute("SELECT COUNT(*) FROM likes WHERE recipe_id=?", (recipeId, ))
				likes = str(cur.fetchone()[0])
				data[recipeId] = {"ID": snippet_id, "description": desc, "code": code,"username": username, "likes": likes}
			db.close()
			return jsonify({"status": 1, "data": data})

		elif popularBool:
			cur = db.cursor()
			cur.execute("SELECT s.orderID, s.title, s.description, s.code, s.username, COUNT(l.username) AS like_count FROM snippets AS s LEFT JOIN likes AS l "
						"ON s.orderID = l.snippet_id GROUP BY s.orderID ORDER BY like_count DESC LIMIT 2")
			snippets = cur.fetchall()
			for snippet in snippets:
				snippet_id = snippet[0]
				data[snippet_id] = {
					"title": snippet[1],
					"description": snippet[2],
					"code": snippet[3],
					"username": snippet[4],
					"likes": str(snippet[5])
				}
			db.close()
			return jsonify({"status": 1, "data": data})

		else:
			cur = db.cursor()
			cur.execute("SELECT * FROM snippets")
			snippets = cur.fetchall()
			for snippet in snippets:
				snippet_id = snippet[4]
				if query in snippet[0].lower() or query in snippet[1].lower() or query in snippet[2].lower():
					data[snippet_id] = {
						"title": snippet[0],
						"description": snippet[1],
						"code": snippet[2],
						"username": snippet[3],
						"likes": str(
							cur.execute("SELECT COUNT(*) FROM likes WHERE snippet_id=?", (snippet_id,)).fetchone()[0])
					}
			db.close()
			return jsonify({"status": 1, "data": data})

	return """
		<h1>Search</h1>
		<form action="" method="post" novalidate>
		<p>
			Set feed=True to see snippets from users you follow. Set popular=True for most liked snippets. Use query to search title, description, or code.
		</p>
			<p>
				Feed: <br>
				<input type = "boolean" name = "feed" size = "32">
			</p>
			<p>
				Popular: <br>
				<input type = "boolean" name = "popular" size = "32">
			</p>
			<p>
				Query: <br>
				<input type = "array" name = "query" size = "32">
			</p>
			<p>
				<input type="submit" value="View">
			</p>
		</form>

		"""
