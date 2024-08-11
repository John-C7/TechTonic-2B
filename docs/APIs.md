## Sample REST APIs
* **Upload Memory Dump:**
  - **Endpoint:** POST /api/memory-dump
  - **Description:** Uploads a memory dump file for analysis.
  - **Request Body:** `{ "file": <memory_dump_file> }`
  - **Response:** `{ "status": "success", "fileId": <file_id> }`

* **Start Memory Analysis:**
  - **Endpoint:** POST /api/analyze
  - **Description:** Initiates memory analysis using a specified plugin.
  - **Request Body:** `{ "fileId": <file_id>, "plugin": <plugin_name> }`
  - **Response:** `{ "status": "analysis_started", "analysisId": <analysis_id> }`

* **Get Analysis Status:**
  - **Endpoint:** GET /api/analysis/{analysisId}/status
  - **Description:** Retrieves the status of an ongoing memory analysis.
  - **Response:** `{ "status": "in_progress" | "completed" | "failed" }`

* **Get Analysis Results:**
  - **Endpoint:** GET /api/analysis/{analysisId}/results
  - **Description:** Fetches the results of a completed memory analysis.
  - **Response:** `{ "status": "success", "results": <analysis_results> }`

* **List Historical Analyses:**
  - **Endpoint:** GET /api/analyses
  - **Description:** Lists all historical analyses performed by the user.
  - **Response:** `{ "analyses": [ { "analysisId": <id>, "date": <timestamp>, "plugin": <plugin_name> } ] }`

## VirusTotal APIs
   
* **Upload file for Malware analysis:**
   - **EndPoint:** POST https://www.virustotal.com/api/v3/files
   - **Description:** Sends the request to VirusTotal API for malware scanning of files
   - **Request:** `headers = {
           "accept": "application/json",
           "content-type": "multipart/form-data"
              }`

* **Recieve the Report of the analysis:**
  - **EndPoint:** GET https://www.virustotal.com/api/v3/files/{id}
  - **Description:** Recieves the the file analysis report from virusTotal 
  - **Response:**`headers = {"accept": "application/json"}`





 