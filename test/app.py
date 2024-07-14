from flask import Flask, request, jsonify
import subprocess
import os
import uuid
import logging
import requests
# from malfinddeep import MalfindDeep
import json

VIRUSTOTAL_API_KEY = 'your_virustotal_api_key_here'
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

# @app.route('/api/analyze', methods=['POST'])
# def start_memory_analysis():
#     data = request.json
#     file_id = data.get('fileId')
#     plugin = data.get('plugin')
#     file_path = os.path.join(UPLOAD_FOLDER, file_id)
#     if not os.path.exists(file_path):
#         return jsonify({"status": "error", "message": "File not found"}), 404
#     analysis_id = str(uuid.uuid4())
#     analyses[analysis_id] = {
#         "status": "in_progress",
#         "fileId": file_id,
#         "plugin": plugin
#     }
#     try:
#         results = run_volatility_commands(file_path, [plugin])
#         analyses[analysis_id]["status"] = "completed"
#         analyses[analysis_id]["results"] = results
#     except Exception as e:
#         analyses[analysis_id]["status"] = "failed"
#         analyses[analysis_id]["error"] = str(e)
#     return jsonify({"status": "analysis_started", "analysisId": analysis_id}), 202

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
        # if plugin == 'malfinddeep':
        #     malfind_deep = MalfindDeep(config=None)  
        #     results = malfind_deep.run(file_path)

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
@app.route('/api/scan-file', methods=['POST'])
def scan_file_with_virustotal():
    data = request.json
    file_id = data.get('fileId')
    file_path = os.path.join(UPLOAD_FOLDER, file_id)
    
    if not os.path.exists(file_path):
        return jsonify({"status": "error", "message": "File not found"}), 404
    
    try:
        files = {'file': (file_id, open(file_path, 'rb'))}
        params = {'apikey': VIRUSTOTAL_API_KEY}
        response = requests.post(VIRUSTOTAL_SCAN_URL, files=files, params=params)
        
        if response.status_code == 200:
            scan_result = response.json()
            return jsonify({"status": "success", "scanResult": scan_result}), 200
        else:
            return jsonify({"status": "error", "message": "Scan failed"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    


### Virus total Analysis on the dump file image 

# @app.route('api/analyzevirus', methods=['POST'])
# def analyze_files():
#     # Get the uploaded files from the request
#     uploaded_files = request.files.getlist('files')

#     # Create a directory to store the analysis results
#     results_dir = Path('analysis_results')
#     results_dir.mkdir(exist_ok=True)

#     # Analyze each uploaded file
#     for uploaded_file in uploaded_files:
#         # Save the uploaded file
#         file_path = results_dir / uploaded_file.filename
#         uploaded_file.save(file_path)

#         # Perform the VirusTotal analysis
#         f_hash = hash_it(file_path, "sha256")
#         response = vt_get_data(f_hash)

#         if response.status_code == 404:
#             if file_path.stat().st_size > 32000000:
#                 response = vt_get_data(vt_get_analyses(vt_post_files(file_path, vt_get_upload_url())))
#             else:
#                 response = vt_get_data(vt_get_analyses(vt_post_files(file_path)))

#         if response.status_code == 200:
#             parsed_response = parse_response(response)
#             json_file_name = f"{file_path.stem}.json"
#             json_file_path = results_dir / json_file_name
#             with open(json_file_path, "w") as json_file:
#                 json.dump(parsed_response, json_file, indent=2)

#             # Generate the analysis report
#             report = bar(parsed_response)

#             # Return the analysis report and the JSON file
#             return send_file(json_file_path, as_attachment=True), report
#         else:
#             return f"Error analyzing file: {response.status_code}", 500

#     return "All files analyzed successfully", 200



#### ////// URL Analysis //////

@app.route('/api/scan-urls', methods=['POST'])
def scan_urls_from_json():
    # Get the JSON file from the request
    json_file = request.files['json_file']
    
    # Load the URLs from the JSON file
    urls = json.load(json_file)['urls']
    
    # Initialize an empty list to store the scan results
    scan_results = []
    
    # Scan each URL using the VirusTotal API
    for url in urls:
        params = {
            'url': url,
            'apikey': VIRUSTOTAL_API_KEY
        }
        response = requests.post(VIRUSTOTAL_URL_SCAN_URL, data=params)
        scan_results.append({
            'url': url,
            'scan_id': response.json()['scan_id'],
            'permalink': response.json()['permalink']
        })
    
    # Return the scan results as a JSON response
    return jsonify({'scan_results': scan_results})

def get_url_report(url):
    params = {
        'resource': url,
        'apikey': 'bbf5711c4ca45931d99e05e1b3fb23dbda26ae683d0db5d44ea5e55e38b9d6aa'
    }
    response = requests.get(VIRUSTOTAL_URL_REPORT_URL, params=params)
    return response.json()


@app.route('/api/url-report', methods=['POST'])
def get_report_for_url():
    url = request.json['url']
    report = get_url_report(url)
    return jsonify(report)
if __name__ == '__main__':
    app.run(debug=True)
