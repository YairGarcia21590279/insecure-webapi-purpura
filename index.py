import json
import random
import hashlib
import mysql.connector
import base64
import shutil
import bcrypt
from datetime import datetime
from pathlib import Path
from bottle import route, run, template, post, request, static_file, default_app


def loadDatabaseSettings(pathjs):
	pathjs = Path(pathjs)
	sjson = False
	if pathjs.exists():
		with pathjs.open() as data:
			sjson = json.load(data)
	return sjson


def getToken():
	tiempo = datetime.now().timestamp()
	numero = random.random()
	cadena = str(tiempo) + str(numero)
	numero2 = random.random()
	cadena2 = str(numero)+str(tiempo)+str(numero2)
	m = hashlib.sha1()
	m.update(cadena.encode())
	P = m.hexdigest()
	m = hashlib.md5()
	m.update(cadena.encode())
	Q = m.hexdigest()
	return f"{P[:20]}{Q[20:]}"


# ==========================================
# VULNERABILIDAD 2 PARCHEADA: MD5 -> BCRYPT
# Ahora usa bcrypt para hashear passwords
# ==========================================

@post('/Registro')
def Registro():
	dbcnf = loadDatabaseSettings('db.json')
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)
	
	if not request.json:
		return {"R":-1}
	
	R = 'uname' in request.json and 'email' in request.json and 'password' in request.json
	if not R:
		return {"R":-1}
	
	R = False
	try:
		cursor = db.cursor()
		
		# PARCHE: Usar bcrypt en lugar de MD5
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
		print(e) 
		return {"R":-2}
	
	return {"R":0,"D":R}


@post('/Login')
def Login():
	dbcnf = loadDatabaseSettings('db.json')
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)
	
	if not request.json:
		return {"R":-1}
	
	R = 'uname' in request.json and 'password' in request.json
	if not R:
		return {"R":-1}
	
	R = False
	try:
		cursor = db.cursor()
		
		# PARCHE: Obtener el hash almacenado para validar con bcrypt
		cursor.execute(
			'SELECT id, password FROM Usuario WHERE uname = %s',
			(request.json["uname"],)
		)
		R = cursor.fetchall()
		cursor.close()
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-2}
	
	if not R:
		db.close()
		return {"R":-3}
	
	# PARCHE: Validar password con bcrypt.checkpw
	user_id = R[0][0]
	stored_hash = R[0][1]
	
	# Verificar si stored_hash es bytes o string
	if isinstance(stored_hash, str):
		stored_hash = stored_hash.encode('utf-8')
	
	try:
		if not bcrypt.checkpw(request.json["password"].encode('utf-8'), stored_hash):
			db.close()
			return {"R":-3}
	except Exception as e:
		print(e)
		db.close()
		return {"R":-3}
	
	T = getToken()
	
	try:
		cursor = db.cursor()
		cursor.execute('DELETE FROM AccesoToken WHERE id_Usuario = %s', (user_id,))
		cursor.execute('INSERT INTO AccesoToken VALUES(%s, %s, now())', (user_id, T))
		db.commit()
		cursor.close()
		db.close()
		return {"R":0,"D":T}
	except Exception as e:
		print(e)
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
	
	dbcnf = loadDatabaseSettings('db.json')
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)

	TKN = request.json['token']
	
	R = False
	try:
		cursor = db.cursor()
		cursor.execute('SELECT id_Usuario FROM AccesoToken WHERE token = %s', (TKN,))
		R = cursor.fetchall()
		cursor.close()
	except Exception as e: 
		print(e)
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
		
		nueva_ruta = f"img/{idImagen}.{request.json['ext']}"
		cursor.execute('UPDATE Imagen SET ruta = %s WHERE id = %s', (nueva_ruta, idImagen))
		
		db.commit()
		cursor.close()
		db.close()
		
		# Mover archivo a su nueva locacion
		shutil.move(f'tmp/{id_Usuario}', nueva_ruta)
		return {"R":0,"D":idImagen}
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-3}


@post('/Descargar')
def Descargar():
	dbcnf = loadDatabaseSettings('db.json')
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)
	
	if not request.json:
		return {"R":-1}
	
	R = 'token' in request.json and 'id' in request.json
	if not R:
		return {"R":-1}
	
	TKN = request.json['token']
	idImagen = request.json['id']
	
	R = False
	try:
		cursor = db.cursor()
		cursor.execute('SELECT id_Usuario FROM AccesoToken WHERE token = %s', (TKN,))
		R = cursor.fetchall()
		cursor.close()
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-2}
	
	if not R:
		db.close()
		return {"R":-2}
	
	try:
		cursor = db.cursor()
		cursor.execute('SELECT name, ruta FROM Imagen WHERE id = %s', (idImagen,))
		R = cursor.fetchall()
		cursor.close()
		db.close()
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-3}
	
	if not R:
		return {"R":-3}
	
	return static_file(R[0][1], Path(".").resolve())


# Configuración para gunicorn
app = application = default_app()

if __name__ == '__main__':
    run(host='0.0.0.0', port=8080, debug=True)
