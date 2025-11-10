import jwt, datetime, os
from flask import Flask, request, jsonify
from flask_mysqldb import MySQL

app = Flask(__name__)

# --- Secure configuration ---
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD', 'password')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB', 'mydb')
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'  

mysql = MySQL(app)

@app.route("/login", methods=["POST"])
def login():
    auth = request.authorization
    if not auth:
        return jsonify({"error": "missing credentials"}), 401

    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT email, password FROM user WHERE email = %s", (auth.username,))
        user_row = cur.fetchone()
    except Exception as e:
        app.logger.error(f"MySQL query failed: {e}")
        return jsonify({"error": "database error"}), 500
    finally:
        cur.close()

    if not user_row:
        return jsonify({"error": "invalid credentials"}), 401

    email = user_row["email"]
    password = user_row["password"]

    if auth.username != email or auth.password != password:
        return jsonify({"error": "invalid credentials"}), 401

    token = createJWT(auth.username, os.getenv("JWT_SECRET"), True)
    return jsonify({"token": token}), 200

def createJWT(username, secret, authz):
    return jwt.encode(
        {
            "username": username,
            "exp": datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=1), # 1 day expiration
            "iat": datetime.datetime.now(tz=datetime.timezone.utc), # issued at
            "admin": authz,
        },
        secret,
        algorithm="HS256",
    )
    
@app.route("/validate", methods=["POST"])
def validate():
    auth_header = request.headers.get("Authorization")

    if not auth_header:
        return jsonify({"error": "missing credentials"}), 401

    try:
        encoded_jwt = auth_header.split(" ")[1]
        decoded = jwt.decode(
            encoded_jwt, os.getenv("JWT_SECRET"), algorithms=["HS256"]
        )
        return jsonify(decoded), 200

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "token expired"}), 403
    except jwt.InvalidTokenError:
        return jsonify({"error": "not authorized"}), 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)