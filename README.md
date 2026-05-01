Plurilock Sentinel
    
    Plurilock Sentinel is a tool that turns natural‑language descriptions of malware or threat characteristics into fully‑qualified YARA rules.  
    It uses large language models (via OpenRouter) to generate, verify, review and, if desired, deploy those rules by scanning a target directory.
    
    
    
    Table of contents  
    - Overview  
    - Main components  
    - Setup  
    - Usage  
      - Backend – CLI  
      - Frontend – Web interface  
    - Configuration  
    - Output  
    - Notes  
    - License
    
    
    
    Overview  
    
    Sentinel automates the full pipeline:  
    1. Generate YARA rule from a text prompt.  
    2. Verify the syntax with yarac.  
    3. Review with a second LLM pass.  
    4. Deploy by stored in rules/ and optionally scanning an input folder.
    
    
    
    Components
    
    | File | Purpose |
    |------|---------|
    | backend/LanguageProcessor.py | Core logic – generation, verification, review, and deployment. |
    | backend/Deployer.py | Uses the generated rules to scan files in a directory. |
    | backend/Verifier.py | Wrapper around yarac that checks syntax. |
    | frontend/app.py | NiceGUI web interface for non‑CLI users. |
    | rules/ | Folder where all YARA files are written (timestamped filenames). |
    
    
    
    Setup
    
    1. Install dependencies  
       bash
       pip install -r requirements.txt
       
    
    2. Configure OpenRouter API key  
       Edit config.ini:
    
       ini
       [API]
       api_key = "your_openrouter_api_key"
       
    
    3. Install YARA compiler (yarac)  
       Ubuntu/Debian: sudo apt install yara  
       macOS: brew install yara  
       Windows: Download from <https://virustotal.github.io/yara/> and add to PATH.
    
    
    
    Usage
    
    Backend – Command Line
    
    bash
    python backend/LanguageProcessor.py
    
    
    Follow the prompts:  
    1. Supply a threat description.  
    2. Verify the rule.  
    3. Review the rule.  
    4. Deploy (writes file + optional scan).  
    5. If you choose to scan, enter the directory path when prompted.
    
    Frontend – Web Interface
    
    bash
    cd frontend
    python app.py
    
    
    Open <http://localhost:8081> in your browser.
    
    1. Enter a malware/threat description.  
    2. Optionally attach a context file or specify a scan directory.  
    3. Click RUN.  
    4. View live logs and results in the UI.
    
    
    
    Configuration
    
    | File | Purpose |
    |------|---------|
    | config.ini | OpenRouter API key (and other global settings). |
    | SentinelGen | Prompt template for rule generation LLM. |
    | SentinelRvw | Prompt template for rule review LLM. |
    
    These files are plain‑text; edit them to tweak model behaviour or add extra instructions.
    
    
    
    Output
    
    - YARA files are written to rules/ with a timestamped name, e.g. rule-2026-05-01-1405.yara.  
    - Scan results are printed to the console (CLI) or shown in the frontend log panel.
    
    
    
    Notes
    
    - Requires an internet connection for LLM calls.  
    - Free tier models may hit rate limits; a paid plan is recommended for heavy usage.  
    - Always review generated rules before deploying them in production.
    
    
    
    License
    
    
    MIT License
      
    This project is provided “as‑is” for educational and defensive security purposes.
