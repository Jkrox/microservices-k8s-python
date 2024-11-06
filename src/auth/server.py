from jose import jwt, JWTError
import os
import datetime
from flask import Flask, request
from flask_mysqldb import MySQL

server = Flask(__name__)
mysql = MySQL(server)

# config
server.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
server.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
server.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
server.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
server.config['MYSQL_PORT'] = int(os.getenv('MYSQL_PORT'))

@server.route("/login", methods=["POST"])
def login() -> None: 
    auth = request.authorization
    if not auth: 
        return "Missing credentials", 401
    
    cur= mysql.connection.cursor()
    res = cur.execute(
        f"SELECT email, password FROM user WHERE email = {auth.username}"
    )
    if res > 0: 
        user_row = cur.fetchone()
        email = user_row[0]
        password = user_row[1]
        
        if auth.username != email or auth.password != password: 
            return "Invalid credentials", 401
        else:
            return createJWT(auth.username, os.environ.get("JWT_SECRET"), True)
        
    else:
        return "User not found", 404
    
@server.route("/validate", methods=["POST"])
def validate() -> None: 
    encoded_jwt = request.headers["Authorization"]
    if not encoded_jwt:
        return "Missing token", 401
    
    encoded_jwt = encoded_jwt.split(" ")[1]
    try:
        decoded = jwt.decode(encoded_jwt, os.environ.get("JWT_SECRET"), algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return "Token expired", 401
    except JWTError:
        return "Not authorized", 401
    
    return decoded, 200

def createJWT(username: str, secret: str, is_admin: bool) -> str:
    return jwt.encode(
        {
            "username": username,
            "exp": datetime.date.now(tz=datetime.timezone.utc) + datetime.timedelta(days=1),
            "iat": datetime.date.now(tz=datetime.timezone.utc),
            "admin": is_admin
        },
        secret,
        algorithm="HS256"
    )
    
if __name__ == "__main__":
    server.run(host="0.0.0.0", port=5000)