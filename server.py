from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import json
import os
from datetime import datetime
import sqlite3
import random
import string

app = Flask(__name__)
CORS(app)

DB_PATH = 'scanner_data.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pin TEXT,
            user TEXT,
            pc_name TEXT,
            data TEXT,
            os TEXT,
            ip TEXT,
            hwid TEXT,
            pc_start_time TEXT,
            sysmain TEXT,
            pcavsc TEXT,
            dps TEXT,
            diagtrack TEXT,
            lssas TEXT,
            explorer TEXT,
            cheats TEXT,
            dns_cache TEXT,
            web_history TEXT,
            processos TEXT,
            minecraft_clients TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'pending'
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS pins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pin TEXT UNIQUE,
            user TEXT,
            game TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            used_at TIMESTAMP,
            result TEXT,
            scan_id INTEGER
        )
    ''')
    
    conn.commit()
    conn.close()

init_db()

def gerar_pin():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/gerar_pin', methods=['POST'])
def gerar_pin():
    data = request.json
    game = data.get('game', 'Minecraft')
    user = data.get('user', 'Staff')
    pin = gerar_pin()
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO pins (pin, user, game, status) VALUES (?, ?, ?, "pending")', (pin, user, game))
    conn.commit()
    conn.close()
    
    return jsonify({'pin': pin, 'game': game, 'user': user})

@app.route('/api/validar_pin', methods=['POST'])
def validar_pin():
    data = request.json
    pin = data.get('pin')
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM pins WHERE pin = ? AND status = "pending"', (pin,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return jsonify({'valid': True, 'game': result[3]})
    return jsonify({'valid': False})

@app.route('/api/enviar_scan', methods=['POST'])
def enviar_scan():
    data = request.json
    pin = data.get('pin')
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM pins WHERE pin = ? AND status = "pending"', (pin,))
    pin_result = cursor.fetchone()
    
    if not pin_result:
        conn.close()
        return jsonify({'error': 'PIN inválido ou já utilizado'}), 400
    
    pin_id = pin_result[0]
    
    cursor.execute('''
        INSERT INTO scans (
            pin, user, pc_name, data, os, ip, hwid,
            pc_start_time, sysmain, pcavsc, dps, diagtrack,
            lssas, explorer, cheats, dns_cache, web_history,
            processos, minecraft_clients, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'finished')
    ''', (
        pin,
        data.get('user', 'N/A'),
        data.get('pc_name', 'N/A'),
        data.get('data', ''),
        data.get('os', 'N/A'),
        data.get('ip', 'N/A'),
        data.get('hwid', 'N/A'),
        data.get('pc_start_time', 'N/A'),
        data.get('sysmain', 'N/A'),
        data.get('pcavsc', 'N/A'),
        data.get('dps', 'N/A'),
        data.get('diagtrack', 'N/A'),
        json.dumps(data.get('lssas', [])),
        json.dumps(data.get('explorer', [])),
        json.dumps(data.get('cheats', [])),
        json.dumps(data.get('dns_cache', [])),
        json.dumps(data.get('web_history', [])),
        json.dumps(data.get('processos', [])),
        json.dumps(data.get('minecraft_clients', []))
    ))
    
    scan_id = cursor.lastrowid
    
    cursor.execute('''
        UPDATE pins 
        SET status = 'finished', used_at = CURRENT_TIMESTAMP, scan_id = ?, result = ?
        WHERE id = ?
    ''', (scan_id, f"Scan #{scan_id}", pin_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'scan_id': scan_id})

@app.route('/api/pins', methods=['GET'])
def get_pins():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM pins ORDER BY created_at DESC')
    rows = cursor.fetchall()
    conn.close()
    
    pins = []
    for row in rows:
        pins.append({
            'id': row[0],
            'pin': row[1],
            'user': row[2],
            'game': row[3],
            'status': row[4],
            'created_at': row[5],
            'used_at': row[6],
            'result': row[7],
            'scan_id': row[8]
        })
    
    return jsonify(pins)

@app.route('/api/scans', methods=['GET'])
def get_scans():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scans ORDER BY created_at DESC')
    rows = cursor.fetchall()
    conn.close()
    
    scans = []
    for row in rows:
        scans.append({
            'id': row[0],
            'pin': row[1],
            'user': row[2],
            'pc_name': row[3],
            'data': row[4],
            'os': row[5],
            'ip': row[6],
            'hwid': row[7],
            'pc_start_time': row[8],
            'sysmain': row[9],
            'pcavsc': row[10],
            'dps': row[11],
            'diagtrack': row[12],
            'lssas': json.loads(row[13]) if row[13] else [],
            'explorer': json.loads(row[14]) if row[14] else [],
            'cheats': json.loads(row[15]) if row[15] else [],
            'dns_cache': json.loads(row[16]) if row[16] else [],
            'web_history': json.loads(row[17]) if row[17] else [],
            'processos': json.loads(row[18]) if row[18] else [],
            'minecraft_clients': json.loads(row[19]) if row[19] else [],
            'created_at': row[20],
            'status': row[21]
        })
    
    return jsonify(scans)

@app.route('/api/scan/<int:scan_id>', methods=['GET'])
def get_scan(scan_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify({
        'id': row[0],
        'pin': row[1],
        'user': row[2],
        'pc_name': row[3],
        'data': row[4],
        'os': row[5],
        'ip': row[6],
        'hwid': row[7],
        'pc_start_time': row[8],
        'sysmain': row[9],
        'pcavsc': row[10],
        'dps': row[11],
        'diagtrack': row[12],
        'lssas': json.loads(row[13]) if row[13] else [],
        'explorer': json.loads(row[14]) if row[14] else [],
        'cheats': json.loads(row[15]) if row[15] else [],
        'dns_cache': json.loads(row[16]) if row[16] else [],
        'web_history': json.loads(row[17]) if row[17] else [],
        'processos': json.loads(row[18]) if row[18] else [],
        'minecraft_clients': json.loads(row[19]) if row[19] else [],
        'created_at': row[20],
        'status': row[21]
    })

@app.route('/api/status')
def get_status():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM scans')
    total_scans = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM scans WHERE cheats != "[]" AND cheats IS NOT NULL')
    detections = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM pins')
    total_pins = cursor.fetchone()[0]
    conn.close()
    
    return jsonify({
        'total_scans': total_scans,
        'detections': detections,
        'total_pins': total_pins,
        'unique_cheats': 0
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
