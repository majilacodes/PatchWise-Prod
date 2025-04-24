# PatchWise: OS Vulnerability Assessment and Remediation System

PatchWise is an intelligent vulnerability assessment and remediation platform powered by RAG (Retrieval Augmented Generation) and AI analysis. It helps identify, analyze, and remediate security vulnerabilities in your system.

## Features

- **System Scanning**: Collects information about your operating system, hardware, and installed packages
- **Vulnerability Detection**: Fetches latest vulnerabilities from the National Vulnerability Database (NVD)
- **AI-Powered Analysis**: Uses RAG and LLM to analyze vulnerabilities and provide personalized remediation steps
- **Interactive Dashboard**: Visualizes system information and vulnerability statistics
- **Security Assistant**: AI chatbot for answering security-related questions
- **Detailed Reports**: Generates comprehensive vulnerability reports with mitigation steps
- **Voice Input**: Optional voice interaction for asking security questions

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/PatchwiseOS-Stapp-Dep.git
   cd PatchwiseOS-Stapp-Dep
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Create a `.env` file with your API keys:
   ```
   NVD_API_KEY=your_nvd_api_key
   GOOGLE_API_KEY=your_google_api_key
   ```

## Usage

1. Start the application:
   ```
   streamlit run app.py
   ```

2. Open your browser and navigate to `http://localhost:8501`

3. Use the interface to:
   - Scan your system for vulnerabilities
   - View detailed vulnerability information
   - Generate mitigation reports
   - Chat with the security assistant

## System Requirements

- Python 3.8 or higher
- 4GB RAM minimum (8GB recommended)
- Internet connection for vulnerability database access
- Google API key for Gemini LLM access
- Optional: NVD API key for higher rate limits

## Project Structure

- `app.py`: Main application file
- `voice_utils.py`: Voice recognition utilities
- `requirements.txt`: Project dependencies
- `db/chroma_db/`: Vector database for storing system information and vulnerabilities

## Technologies Used

- **Streamlit**: Web interface
- **LangChain**: RAG implementation
- **Google Gemini**: LLM for vulnerability analysis
- **ChromaDB**: Vector database
- **Sentence Transformers**: Embedding model
- **Plotly**: Data visualization
- **NVD API**: Vulnerability data source

## License

© 2025 PatchWise Security

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.