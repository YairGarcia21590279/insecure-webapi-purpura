import json
import secrets
import hashlib
import mysql.connector
import base64
import shutil
import bcrypt
import os
import re
from datetime import datetime
from pathlib import Path
from bottle import route, run, template, post, request, static_file, default_app
from dotenv import load_dotenv

# ==========================================
# VULNERABILIDADES PARCHEADAS (PLAN B):
# 1. IDOR en /Descargar (A01)
# 2. Validacion de Email (A04)
# 3. Validacion de Extensiones (A04)
# 4. Generacion de Token Debil (A02)
# ==========================================

load_dotenv()


def loadDatabaseSettings():
	"""
	Carga configuración de BD desde variables de entorno
	"""
	return {
		'host': os.getenv('DB_HOST', 'localhost'),
		'port': int(os.getenv('DB_PORT', 3306)),
		'dbname': os.getenv('DB_NAME'),
		'user': os.getenv('DB_USER'),
		'password': os.getenv('DB_PASSWORD')
	}


def getToken():
	"""
	PARCHE VULNERABILIDAD 4: Token criptográficamente seguro
	Usa secrets en lugar de random.random()
	"""
	return secrets.token_urlsafe(32)


@post('/Registro')
def Registro():
	dbcnf = loadDatabaseSettings()
	db = mysql.connector.connect(
		host=dbcnf['host'], 
		port=dbcnf['port'],
		database=dbcnf['dbname'],
		user=dbcnf['user'],
		password=dbcnf['password']
	)
	
	if not request.json:
		return {"R":-1}
	
	R = 'uname' in request.json and 'email' in request.json and 'password' in request.json
	if not R:
		return {"R":-1}
	
	# ========== PARCHE VULNERABILIDAD 2: Validacion de Email ==========
	email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
	if not re.match(email_regex, request.json['email']):
		return {"R":-1, "error":"Email invalido"}
	# ===================================================================
	
	R = False
	try:
		cursor = db.cursor()
		
		password_hash = bcrypt.hashpw(
			request.json["password"].encode('utf-8'), 
			bcrypt.gensalt()
		)
		
		cursor.execute(
			'INSERT INTO Usuario VALUES(null, %s, %s, %s)',
			(request.json["uname"], request.json["email"], password_hash)
		)
		R = cursor.lastrowid
		db.commit()
		cursor.close()
		db.close()
	except Exception as e:
		return {"R":-2}
	
	return {"R":0,"D":R}


@post('/Login')
def Login():
	dbcnf = loadDatabaseSettings()
	db = mysql.connector.connect(
		host=dbcnf['host'], 
		port=dbcnf['port'],
		database=dbcnf['dbname'],
		user=dbcnf['user'],
		password=dbcnf['password']
	)
	
	if not request.json:
		return {"R":-1}
	
	R = 'uname' in request.json and 'password' in request.json
	if not R:
		return {"R":-1}
	
	R = False
	try:
		cursor = db.cursor()
		
		cursor.execute(
			'SELECT id, password FROM Usuario WHERE uname = %s',
			(request.json["uname"],)
		)
		R = cursor.fetchall()
		cursor.close()
	except Exception as e: 
		db.close()
		return {"R":-2}
	
	if not R:
		db.close()
		return {"R":-3}
	
	user_id = R[0][0]
	stored_hash = R[0][1]
	
	if isinstance(stored_hash, str):
		stored_hash = stored_hash.encode('utf-8')
	
	try:
		if not bcrypt.checkpw(request.json["password"].encode('utf-8'), stored_hash):
			db.close()
			return {"R":-3}
	except Exception as e:
		db.close()
		return {"R":-3}
	
	T = getToken()  # Ya usa secrets.token_urlsafe()
	
	try:
		cursor = db.cursor()
		cursor.execute('DELETE FROM AccesoToken WHERE id_Usuario = %s', (user_id,))
		cursor.execute('INSERT INTO AccesoToken VALUES(%s, %s, now())', (user_id, T))
		db.commit()
		cursor.close()
		db.close()
		return {"R":0,"D":T}
	except Exception as e:
		db.close()
		return {"R":-4}


@post('/Imagen')
def Imagen():
	tmp = Path('tmp')
	if not tmp.exists():
		tmp.mkdir()
	img = Path('img')
	if not img.exists():
		img.mkdir()
	
	if not request.json:
		return {"R":-1}
	
	R = 'name' in request.json and 'data' in request.json and 'ext' in request.json and 'token' in request.json
	if not R:
		return {"R":-1}
	
	# ========== PARCHE VULNERABILIDAD 3: Validacion de Extensiones ==========
	allowed_extensions = ['png', 'jpg', 'jpeg', 'gif', 'webp']
	ext = request.json['ext'].lower()
	if ext not in allowed_extensions:
		return {"R":-1, "error":"Extension no permitida"}
	# ========================================================================
	
	dbcnf = loadDatabaseSettings()
	db = mysql.connector.connect(
		host=dbcnf['host'], 
		port=dbcnf['port'],
		database=dbcnf['dbname'],
		user=dbcnf['user'],
		password=dbcnf['password']
	)

	TKN = request.json['token']
	
	R = False
	try:
		cursor = db.cursor()
		cursor.execute('SELECT id_Usuario FROM AccesoToken WHERE token = %s', (TKN,))
		R = cursor.fetchall()
		cursor.close()
	except Exception as e: 
		db.close()
		return {"R":-2}
	
	if not R:
		db.close()
		return {"R":-2}
	
	id_Usuario = R[0][0]
	
	with open(f'tmp/{id_Usuario}',"wb") as imagen:
		imagen.write(base64.b64decode(request.json['data'].encode()))
	
	try:
		cursor = db.cursor()
		cursor.execute(
			'INSERT INTO Imagen VALUES(null, %s, "img/", %s)',
			(request.json["name"], id_Usuario)
		)
		cursor.execute('SELECT max(id) as idImagen FROM Imagen WHERE id_Usuario = %s', (id_Usuario,))
		R = cursor.fetchall()
		idImagen = R[0][0]
		
		nueva_ruta = f"img/{idImagen}.{ext}"
		cursor.execute('UPDATE Imagen SET ruta = %s WHERE id = %s', (nueva_ruta, idImagen))
		
		db.commit()
		cursor.close()
		db.close()
		
		shutil.move(f'tmp/{id_Usuario}', nueva_ruta)
		return {"R":0,"D":idImagen}
	except Exception as e: 
		db.close()
		return {"R":-3}


@post('/Descargar')
def Descargar():
	dbcnf = loadDatabaseSettings()
	db = mysql.connector.connect(
		host=dbcnf['host'], 
		port=dbcnf['port'],
		database=dbcnf['dbname'],
		user=dbcnf['user'],
		password=dbcnf['password']
	)
	
	if not request.json:
		return {"R":-1}
	
	R = 'token' in request.json and 'id' in request.json
	if not R:
		return {"R":-1}
	
	TKN = request.json['token']
	idImagen = request.json['id']
	
	# ========== PARCHE VULNERABILIDAD 1: IDOR - Broken Access Control ==========
	# Validar que el usuario del token sea el dueño de la imagen usando JOIN
	R = False
	try:
		cursor = db.cursor()
		cursor.execute('''
			SELECT i.name, i.ruta 
			FROM Imagen i
			JOIN AccesoToken at ON i.id_Usuario = at.id_Usuario
			WHERE i.id = %s AND at.token = %s
		''', (idImagen, TKN))
		R = cursor.fetchall()
		cursor.close()
		db.close()
	except Exception as e: 
		db.close()
		return {"R":-2}
	
	if not R:
		return {"R":-4, "error":"Imagen no encontrada o no tienes permisos"}
	# ===========================================================================
	
	return static_file(R[0][1], Path(".").resolve())


# Configuración para gunicorn
app = application = default_app()

if __name__ == '__main__':
    run(host='0.0.0.0', port=8080, debug=True)
