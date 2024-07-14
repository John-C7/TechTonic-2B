# ForensicLens-A User-Friendly UI For The Volatility Framework

## Objectives
* This project aims to develop a wrapper graphical interface for the Volatility framework, focusing on enhancing usability for memory forensics and analysis.
* Participants will design and implement sample plugins to automate different aspects of memory analysis within the Volatility framework.
* The solution will utilize a REST API architecture, separating backend and frontend modules to ensure scalability and maintainability.
* Users will be able to perform, store, and securely manage historical analysis data through a web application interface.
* The project aims to streamline the process of memory forensics by integrating user-friendly graphical tools with the powerful capabilities of Volatility.


## Challenge

* Memory forensics is crucial in cybersecurity for uncovering malicious activities that evade traditional disk-based forensics.
* The Volatility framework is extensively used for memory analysis, offering a comprehensive range of tools and features.
* It is particularly adept at revealing insights from volatile memory dumps, such as running processes and network connections.
* However, its command-line interface can pose challenges for novice users due to its complexity.
* Additionally, there is a need for a centralized system within Volatility for storing historical analysis data, which could enhance usability and workflow efficiency in cybersecurity investigations.
  
<p align="center">
  <img src="https://miro.medium.com/v2/resize:fit:828/format:webp/1*prcy-oFXTa_ydr7W-uoi9A.gif" alt= Alt text width=400 height="400">
</p>

## About Volatility
* The Volatility Framework is a powerful open-source tool used for analyzing volatile memory dumps.
* It enables forensic investigators and incident responders to extract and examine crucial information from memory snapshots.
* Information includes running processes, network connections, and loaded kernel modules.
* Volatility boasts an extensive plugin architecture that supports various memory dump formats.
* This framework facilitates in-depth memory forensics, assisting in malware analysis, digital investigations, and system memory analysis for security incidents.
  <p align="center">
  <img src="https://miro.medium.com/v2/resize:fit:1024/0*CTQ-uvCdJ6ZUU3Xb.png" alt= Alt text width=400 height="200">
</p>
Link - https://volatility3.readthedocs.io/en/latest/index.html

## Installing Volatility 

1. Clone the latest version of Volatility from GitHub:

```bash
git clone https://github.com/volatilityfoundation/volatility3.git
```

2. See available options:
```python
python3 vol.py -h
```

3. Download the required symbol table
- https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
- https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip
- https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip
  
  For Further Information Refer - https://github.com/volatilityfoundation/volatility3

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

 

  







