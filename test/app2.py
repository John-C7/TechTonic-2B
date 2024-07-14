import logging
import subprocess
import os
import uuid
from flask import Flask, request, jsonify

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

analyses = {}

def run_volatility_commands(memory_dump_path, plugins):
    volatility_path = r'C:\Users\JOHN CHARLES\Desktop\TechTonic Web\TechTonic-2B\backend\volatility3\vol.py'  # Path to your Volatility executable
    results = {}
    plugins=['windows.pslist.PsList',]
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

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    app.run(debug=True)
