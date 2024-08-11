from flask import Flask, request, jsonify, send_file
import subprocess
import os
import uuid
import logging
import requests
import json
from pathlib import Path
from time import sleep
import hashlib

#### Viruss total congigs
VIRUSTOTAL_API_KEY = 'bbf5711c4ca45931d99e05e1b3fb23dbda26ae683d0db5d44ea5e55e38b9d6aa'
VIRUSTOTAL_SCAN_URL = 'https://www.virustotal.com/api/v3/files'
VIRUSTOTAL_URL_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/url/report'
VIRUSTOTAL_URL_SCAN_URL = 'https://www.virustotal.com/vtapi/v2/url/scan'

logging.basicConfig(level=logging.INFO)
app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

analyses = {}

def run_volatility_commands(memory_dump_path, plugins):
    volatility_path = r'C:\Users\JOHN CHARLES\Desktop\TechTonic Web\TechTonic-2B\backend\volatility3\vol.py'  

    ### path to the volatility framework source code 
    results = {}
    plugins = ['windows.pstree.PsTree']

    logging.info(f"Memory dump path: {memory_dump_path}")
    for plugin in plugins:
        command = ['python', volatility_path, '-f', memory_dump_path, plugin]

        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT)
            result = output.decode('utf-8')
            results[plugin] = result
            logging.info(f"Plugin {plugin} output: {result}")
        except subprocess.CalledProcessError as e:
            result = e.output.decode('utf-8')
            results[plugin] = result
            logging.error(f"Error running plugin {plugin}: {result}")
    return results

@app.route('/api/memory-dump', methods=['POST'])
def upload_memory_dump():
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"status": "error", "message": "No selected file"}), 400
    file_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_FOLDER, file_id)
    file.save(file_path)
    return jsonify({"status": "success", "fileId": file_id}), 201

@app.route('/api/analyze', methods=['POST'])
def start_memory_analysis():
    data = request.json
    file_id = data.get('fileId')
    plugin = data.get('plugin')
    file_path = os.path.join(UPLOAD_FOLDER, file_id)
    if not os.path.exists(file_path):
        return jsonify({"status": "error", "message": "File not found"}), 404
    analysis_id = str(uuid.uuid4())
    analyses[analysis_id] = {
        "status": "in_progress",
        "fileId": file_id,
        "plugin": plugin
    }
    try:
        # If plugin is 'url_scan', call scan_urls_from_json
        if plugin == 'url_scan':
            json_file_path = os.path.join(UPLOAD_FOLDER, file_id)
            results = scan_urls_from_json(json_file_path)
        else:
            # Handle other plugins
            results = run_volatility_commands(file_path, [plugin])

        analyses[analysis_id]["status"] = "completed"
        analyses[analysis_id]["results"] = results
    except Exception as e:
        analyses[analysis_id]["status"] = "failed"
        analyses[analysis_id]["error"] = str(e)
    return jsonify({"status": "analysis_started", "analysisId": analysis_id}), 202

@app.route('/api/analysis/<analysis_id>/status', methods=['GET'])
def get_analysis_status(analysis_id):
    analysis = analyses.get(analysis_id)
    if not analysis:
        return jsonify({"status": "error", "message": "Analysis not found"}), 404
    return jsonify({"status": analysis["status"]})

@app.route('/api/analysis/<analysis_id>/results', methods=['GET'])
def get_analysis_results(analysis_id):
    analysis = analyses.get(analysis_id)
    if not analysis:
        return jsonify({"status": "error", "message": "Analysis not found"}), 404
    if analysis["status"] != "completed":
        return jsonify({"status": "error", "message": "Analysis not completed"}), 400
    return jsonify({"status": "success", "results": analysis["results"]})

@app.route('/api/analyses', methods=['GET'])
def list_historical_analyses():
    historical_analyses = [
        {
            "analysisId": analysis_id,
            "date": analysis["date"],
            "plugin": analysis["plugin"]
        } for analysis_id, analysis in analyses.items()
    ]
    return jsonify({"analyses": historical_analyses})

@app.route('/api/raw-memory', methods=['POST'])
def view_raw_memory():
    data = request.json
    file_id = data.get('fileId')
    start_address = data.get('startAddress')
    end_address = data.get('endAddress')
    file_path = os.path.join(UPLOAD_FOLDER, file_id)
    if not os.path.exists(file_path):
        return jsonify({"status": "error", "message": "File not found"}), 404
    try:
        with open(file_path, 'rb') as f:
            f.seek(start_address)
            raw_memory = f.read(end_address - start_address)
        return jsonify({"status": "success", "rawMemory": raw_memory.hex()}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/')
def index():
    return app.send_static_file('index.html')

## VirusTotal API

def hash_it(file, algorithm):
    if algorithm == "sha256":
        hasher = hashlib.sha256()
    elif algorithm == "sha1":
        hasher = hashlib.sha1()
    elif algorithm == "md5":
        hasher = hashlib.md5()
    else:
        raise Exception("Incompatible hash algorithm used. Choose from: sha256 | sha1 | md5")

    with open(file, 'rb') as f:
        hasher.update(f.read())
    return hasher.hexdigest()

def vt_get_data(f_hash):
    url = f"https://www.virustotal.com/api/v3/files/{f_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    while True:
        response = requests.get(url, headers=headers)
        if error_handle(response):
            break
    return response

def vt_post_files(file, url="https://www.virustotal.com/api/v3/files"):
    with open(file, "rb") as f:
        file_bin = f.read()
    upload_package = {"file": (file.name, file_bin)}
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    while True:
        response = requests.post(url, headers=headers, files=upload_package)
        if error_handle(response):
            break
    return response

def vt_get_analyses(response):
    _id = response.json().get("data").get("id")
    url = f"https://www.virustotal.com/api/v3/analyses/{_id}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    while True:
        sleep(60)
        while True:
            response = requests.get(url, headers=headers)
            if error_handle(response):
                break
        if response.json().get("data").get("attributes").get("status") == "completed":
            f_hash = response.json().get("meta").get("file_info").get("sha256")
            return f_hash

def vt_get_upload_url():
    url = "https://www.virustotal.com/api/v3/files/upload_url"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    while True:
        response = requests.get(url, headers=headers)
        if error_handle(response):
            break
    return response.json()["data"]

def error_handle(response):
    if response.status_code == 429:
        sleep(60)
    if response.status_code == 401:
        raise Exception("Invalid API key")
    elif response.status_code not in (200, 404, 429):
        raise Exception(response.status_code)
    else:
        return True
    return False

def parse_response(response):
    json_obj = response.json().get("data").get("attributes")
    output = {}
    output["name"] = json_obj.get("meaningful_name")
    output["stats"] = json_obj.get("last_analysis_stats")
    output["engine_detected"] = {}
    for engine in json_obj.get("last_analysis_results").keys():
        if json_obj.get("last_analysis_results").get(engine).get("category") != "undetected":
            output.get("engine_detected")[engine] = {}
            output.get("engine_detected")[engine]["category"] = json_obj.get("last_analysis_results").get(engine).get("category")
            output.get("engine_detected")[engine]["result"] = json_obj.get("last_analysis_results").get(engine).get("result")
    output["votes"] = json_obj.get("total_votes")
    output["hash"] = {"sha1": json_obj.get("sha1"), "sha254": json_obj.get("sha256"), "md5": json_obj.get("md5")}
    output["first_submission"] = json_obj.get("first_submission_date")
    output["last_submission"] = json_obj.get("last_submission_date")
    output["scans"] = {}
    output["scans"]["last_scan"] = json_obj.get("last_analysis_date")
    output["scans"]["reputation"] = json_obj.get("reputation")
    return output

@app.route("/upload_url_scan", methods=["POST"])
def vt_url_scan():
    urls = json.loads(request.form.get("urls"))
    params = {"apikey": VIRUSTOTAL_API_KEY}
    response = requests.post(VIRUSTOTAL_URL_SCAN_URL, params=params, data={"url": urls})
    return response.json()

@app.route("/upload_url_report", methods=["POST"])
def vt_url_report():
    resource = request.form.get("resource")
    params = {"apikey": VIRUSTOTAL_API_KEY, "resource": resource, "scan": 1}
    response = requests.get(VIRUSTOTAL_URL_REPORT_URL, params=params)
    return response.json()

@app.route('/upload_file_scan', methods=['POST'])
def vt_file_scan():
    file = request.files['file']
    filename = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filename)
    url = vt_get_upload_url()
    response = vt_post_files(file, url=url)
    f_hash = vt_get_analyses(response)
    response = vt_get_data(f_hash)
    output = parse_response(response)
    return jsonify(output)

@app.route('/upload_hash', methods=['POST'])
def vt_hash():
    file = request.files['file']
    hash_alg = request.form.get('hash_alg')
    filename = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filename)
    f_hash = hash_it(filename, hash_alg)
    response = vt_get_data(f_hash)
    if response.status_code == 404:
        url = vt_get_upload_url()
        response = vt_post_files(file, url=url)
        f_hash = vt_get_analyses(response)
        response = vt_get_data(f_hash)
    output = parse_response(response)
    return jsonify(output)

if __name__ == '__main__':
    app.run(debug=True)
