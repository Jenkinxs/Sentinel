**Plurilock Sentinel**


Sentinel - Automated Threat Rule Generation

Overview
Sentinel is a tool that automates the generation of YARA rules from natural language descriptions of malware behavior or threat characteristics.
It uses large language models to generate, verify, and review YARA rules, then optionally scans a specified directory for matches.

Components
- backend/LanguageProcessor.py: Main logic for generating, verifying, and reviewing rules, and deploying them.
- backend/Deployer.py: Scans files using generated YARA rules.
- backend/Verifier.py: Uses yarac to verify YARA syntax.
- frontend/app.py: A web interface built with NiceGUI for interacting with Sentinel.
- rules/: Directory where generated YARA rules are saved.

Setup
1. Install the required Python packages:
   pip install -r requirements.txt

2. Configure the OpenRouter API key:
   - Edit config.ini and set your OpenRouter API key under the [API] section.
   - Example:
     [API]
     api_key = "your_openrouter_api_key"

3. Ensure yarac (YARA compiler) is installed and available in your PATH.
   - On Ubuntu/Debian: sudo apt install yara
   - On macOS: brew install yara
   - On Windows: Download from https://virustotal.github.io/yara/ and add to PATH.

Usage
Backend (Command Line)
- Run the backend directly:
  cd backend
  python LanguageProcessor.py
  Follow the prompts to describe the threat, verify, review, and deploy the rule.
  After deployment, you will be prompted to enter a directory to scan.

Frontend (Web Interface)
- Start the web server:
  cd frontend
  python app.py
- Open a browser and go to http://localhost:8081
- Enter a description of the malware or threat.
- Optionally, provide a context file or scan directory.
- Click "RUN" to start the pipeline.
- View logs and results in the interface.

Configuration
- config.ini: Contains the OpenRouter API key.
- SentinelGen: Prompt used for the rule generation LLM.
- SentinelRvw: Prompt used for the rule review LLM.
- These files are plain text and can be adjusted to change the behavior of the models.

Output
- Generated YARA rules are saved in the rules/ directory with a timestamped filename.
- Scan results are printed to the console (backend) or displayed in the log console (frontend).

Notes
- The tool relies on external LLMs via OpenRouter, so internet access is required.
- The free tier of models may have rate limits; consider using a paid plan for heavy usage.
- Always review generated rules before using them in production.

License
This project is provided as-is for educational and defensive security purposes.
