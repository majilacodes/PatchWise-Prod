import os
import json
import requests
import platform
import subprocess
import psutil
import time
import re
from datetime import datetime, timedelta
from dotenv import load_dotenv
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from langchain.chains import create_history_aware_retriever, create_retrieval_chain
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain_community.vectorstores import Chroma
from langchain_core.documents import Document
from langchain_core.messages import HumanMessage, AIMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_community.embeddings import HuggingFaceEmbeddings
from gtts import gTTS
from io import BytesIO
import base64

# Load environment variables from .env
load_dotenv()

# Configure page settings
st.set_page_config(
    page_title="PatchWise OS - Vulnerability Assessment", 
    page_icon="🛡️", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# Define the persistent directory
current_dir = os.path.dirname(os.path.abspath(__file__))
persistent_directory = os.path.join(current_dir, "db", "chroma_db")
nvd_api_key = os.getenv("NVD_API_KEY", "")  # Get NVD API key from .env
google_api_key = os.getenv("GOOGLE_API_KEY", "")

# Initialize session state
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "vulnerabilities" not in st.session_state:
    st.session_state.vulnerabilities = []
if "system_info" not in st.session_state:
    st.session_state.system_info = None
if "vulnerability_chats" not in st.session_state:
    st.session_state.vulnerability_chats = {}  # Store chat history per vulnerability
if "scan_status" not in st.session_state:
    st.session_state.scan_status = {"last_scan": None, "in_progress": False}
if "error_message" not in st.session_state:
    st.session_state.error_message = None
if "settings" not in st.session_state:
    st.session_state.settings = {
        "llm_provider": "google",
        "severity_filter": "all",
        "days_to_fetch": 7,
        "text_to_speech": False
    }
if "filtered_vulnerabilities" not in st.session_state:
    st.session_state.filtered_vulnerabilities = []

# Function to initialize or get the LLM based on settings
def get_llm():
    if google_api_key:
        return ChatGoogleGenerativeAI(google_api_key=google_api_key, model="gemini-2.0-flash", temperature=0.2)
    else:
        st.error("No API key available. Please set GOOGLE_API_KEY in .env file.")
        return None

# Initialize embedding model
@st.cache_resource
def get_embeddings():
    return HuggingFaceEmbeddings(model_name="sentence-transformers/all-mpnet-base-v2")

embeddings = get_embeddings()

def collect_system_info():
    """Collect detailed system configuration information with error handling"""
    try:
        system_info = {
            "os": {
                "name": platform.system(),
                "version": platform.version(),
                "release": platform.release(),
                "architecture": platform.machine(),
                "distribution": platform.platform(),
            },
            "hardware": {
                "processor": platform.processor() or "Unknown processor",
                "physical_cores": psutil.cpu_count(logical=False) or 0,
                "total_cores": psutil.cpu_count(logical=True) or 0,
                "memory_total": psutil.virtual_memory().total,
                "memory_available": psutil.virtual_memory().available,
                "disk_usage": {
                    "total": psutil.disk_usage('/').total,
                    "used": psutil.disk_usage('/').used,
                    "free": psutil.disk_usage('/').free,
                    "percent": psutil.disk_usage('/').percent
                }
            },
            "software": {
                "python_version": platform.python_version(),
                "installed_packages": []
            },
            "network": {
                "interfaces": []
            },
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Add network interfaces
        try:
            net_if_addrs = psutil.net_if_addrs()
            for interface_name, interface_addresses in net_if_addrs.items():
                interface_info = {"name": interface_name, "addresses": []}
                for address in interface_addresses:
                    if address.family == psutil.AF_LINK:  # MAC address
                        interface_info["mac"] = address.address
                    elif address.family == 2:  # IPv4
                        interface_info["addresses"].append({
                            "ip": address.address,
                            "netmask": address.netmask,
                            "family": "IPv4"
                        })
                    elif address.family == 23:  # IPv6
                        interface_info["addresses"].append({
                            "ip": address.address,
                            "netmask": address.netmask,
                            "family": "IPv6"
                        })
                system_info["network"]["interfaces"].append(interface_info)
        except Exception as e:
            system_info["network"]["error"] = str(e)
        
        # Add installed packages depending on OS
        try:
            if platform.system() == "Windows":
                try:
                    installed_software = subprocess.check_output('wmic product get name,version', shell=True, timeout=15).decode('utf-8', errors='ignore')
                    system_info["software"]["installed_packages"] = [
                        {"name": line.split(None, 1)[0], "version": line.split(None, 1)[1] if len(line.split(None, 1)) > 1 else "Unknown"}
                        for line in installed_software.split('\n') 
                        if line.strip() and "Name" not in line and len(line.split()) >= 1
                    ]
                except subprocess.TimeoutExpired:
                    system_info["software"]["installed_packages"] = [{"name": "Command timed out", "version": "N/A"}]
                except Exception as e:
                    system_info["software"]["installed_packages"] = [{"name": f"Error: {str(e)}", "version": "N/A"}]
            
            elif platform.system() == "Linux":
                try:
                    # For Debian/Ubuntu
                    dpkg_output = subprocess.check_output('dpkg-query -W -f="${Package} ${Version}\n"', shell=True, timeout=15).decode('utf-8', errors='ignore')
                    system_info["software"]["installed_packages"] = [
                        {"name": line.split()[0], "version": line.split()[1] if len(line.split()) > 1 else "Unknown"}
                        for line in dpkg_output.split('\n') if line.strip() and len(line.split()) >= 1
                    ]
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                    try:
                        # For Red Hat/CentOS
                        rpm_output = subprocess.check_output('rpm -qa --qf "%{NAME} %{VERSION}\n"', shell=True, timeout=15).decode('utf-8', errors='ignore')
                        system_info["software"]["installed_packages"] = [
                            {"name": line.split()[0], "version": line.split()[1] if len(line.split()) > 1 else "Unknown"}
                            for line in rpm_output.split('\n') if line.strip() and len(line.split()) >= 1
                        ]
                    except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
                        system_info["software"]["installed_packages"] = [{"name": f"Error: {str(e)}", "version": "N/A"}]
            
            elif platform.system() == "Darwin":  # macOS
                try:
                    # First try using brew
                    brew_output = subprocess.check_output('brew list --versions', shell=True, timeout=15).decode('utf-8', errors='ignore')
                    system_info["software"]["installed_packages"] = [
                        {"name": line.split()[0], "version": " ".join(line.split()[1:]) if len(line.split()) > 1 else "Unknown"}
                        for line in brew_output.split('\n') if line.strip() and len(line.split()) >= 1
                    ]
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                    try:
                        # Try with system_profiler for installed apps
                        app_output = subprocess.check_output('system_profiler SPApplicationsDataType -json', shell=True, timeout=15).decode('utf-8', errors='ignore')
                        app_data = json.loads(app_output)
                        if 'SPApplicationsDataType' in app_data:
                            system_info["software"]["installed_packages"] = [
                                {"name": app.get("_name", "Unknown"), "version": app.get("version", "Unknown")}
                                for app in app_data['SPApplicationsDataType']
                            ]
                    except Exception as e:
                        system_info["software"]["installed_packages"] = [{"name": f"Error: {str(e)}", "version": "N/A"}]
        except Exception as e:
            system_info["software"]["error"] = str(e)
            system_info["software"]["installed_packages"] = [{"name": "Error retrieving packages", "version": "N/A"}]
        
        return system_info
    except Exception as e:
        # Return a minimal system info object with error information
        return {
            "os": {
                "name": platform.system() if 'platform' in globals() else "Unknown",
                "version": "Error",
                "release": "Error",
                "architecture": "Error",
                "distribution": "Error",
            },
            "hardware": {
                "processor": "Error",
                "physical_cores": 0,
                "total_cores": 0,
                "memory_total": 0,
                "memory_available": 0
            },
            "software": {
                "python_version": platform.python_version() if 'platform' in globals() else "Unknown",
                "error": str(e)
            },
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

def store_system_info():
    """Store system information in the vector database with proper error handling"""
    try:
        system_info = collect_system_info()
        st.session_state.system_info = system_info
        
        # Convert system info to documents
        documents = []
        
        # Create document for OS info
        os_text = f"Operating System: {system_info['os']['name']} {system_info['os']['version']} {system_info['os']['release']} ({system_info['os']['architecture']})"
        documents.append(Document(
            page_content=os_text,
            metadata={"source": "system_info", "category": "os", "timestamp": system_info['timestamp']}
        ))
        
        # Create document for hardware info
        hardware_text = (f"Hardware: Processor: {system_info['hardware']['processor']}, "
                          f"Physical cores: {system_info['hardware']['physical_cores']}, "
                          f"Total cores: {system_info['hardware']['total_cores']}, "
                          f"Memory Total: {system_info['hardware']['memory_total'] // (1024*1024*1024)} GB")
        documents.append(Document(
            page_content=hardware_text,
            metadata={"source": "system_info", "category": "hardware", "timestamp": system_info['timestamp']}
        ))
        
        # Create documents for installed packages (chunked in groups of 20)
        if "installed_packages" in system_info["software"] and isinstance(system_info["software"]["installed_packages"], list):
            packages = system_info["software"]["installed_packages"]
            for i in range(0, len(packages), 20):
                chunk = packages[i:i+20]
                package_text = "Installed packages: " + ", ".join([f"{pkg.get('name', 'Unknown')} {pkg.get('version', '')}" for pkg in chunk])
                documents.append(Document(
                    page_content=package_text,
                    metadata={"source": "system_info", "category": "software", "chunk_id": i//20, "timestamp": system_info['timestamp']}
                ))
        
        # Create the vector store directory if it doesn't exist
        os.makedirs(os.path.dirname(persistent_directory), exist_ok=True)
        
        # Check if the database already exists
        if os.path.exists(persistent_directory):
            # Load the existing vector store
            db = Chroma(persist_directory=persistent_directory, embedding_function=embeddings)
            # Add the new system info documents
            db.add_documents(documents)
        else:
            # Create a new vector store
            db = Chroma.from_documents(
                documents=documents,
                embedding=embeddings,
                persist_directory=persistent_directory
            )
        
        # Persist the vector store
        db.persist()
        return len(documents), None  # Success
    except Exception as e:
        return 0, str(e)  # Return error message

def fetch_vulnerabilities():
    """Fetch latest OS vulnerabilities from NVD database with better error handling"""
    try:
        system_info = st.session_state.system_info
        if not system_info:
            return [], "System information not available. Please scan your system first."
        
        os_name = system_info['os']['name'].lower()
        
        # Map internal OS names to CVE searchable terms
        os_search_terms = {
            "windows": "windows",
            "linux": "linux",
            "darwin": "macos"
        }
        
        search_term = os_search_terms.get(os_name, os_name)
        
        # Calculate the date based on user settings
        days_to_fetch = st.session_state.settings.get("days_to_fetch", 7)
        days_ago = (datetime.now() - timedelta(days=days_to_fetch)).strftime("%Y-%m-%dT%H:%M:%S.000")
        current_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.000")
        
        # Set up the NVD API request
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": search_term,
            "pubStartDate": days_ago,
            "pubEndDate": current_time
        }
        
        # Only add API key header if it exists in environment variables
        headers = {}
        if nvd_api_key and nvd_api_key.strip():
            headers["apiKey"] = nvd_api_key
        
        response = requests.get(url, params=params, headers=headers, timeout=30)
        
        # Add a delay to respect rate limits when not using API key
        if not nvd_api_key or not nvd_api_key.strip():
            time.sleep(6)  # NVD has a rate limit of 10 requests per minute without API key
            
        if response.status_code == 200:
            vulnerabilities = response.json().get('vulnerabilities', [])
            
            # Convert to documents and store in vector database
            documents = []
            for vuln in vulnerabilities:
                try:
                    cve = vuln.get('cve', {})
                    cve_id = cve.get('id', 'Unknown')
                    descriptions = cve.get('descriptions', [])
                    
                    # Find English description
                    description = "No description available"
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            description = desc.get('value', 'No description available')
                            break
                    
                    # Get metrics if available
                    metrics = cve.get('metrics', {})
                    cvss_data = None
                    
                    # Try to get CVSS v3.1 data first, then v3.0, then v2.0
                    if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                        cvss_data = metrics['cvssMetricV31'][0]
                        cvss_version = "3.1"
                    elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                        cvss_data = metrics['cvssMetricV30'][0]
                        cvss_version = "3.0"
                    elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                        cvss_data = metrics['cvssMetricV2'][0]
                        cvss_version = "2.0"
                    
                    base_score = "N/A"
                    severity = "N/A"
                    vector = "N/A"
                    
                    if cvss_data and 'cvssData' in cvss_data:
                        base_score = cvss_data['cvssData'].get('baseScore', 'N/A')
                        severity = cvss_data['cvssData'].get('baseSeverity', 'N/A')
                        vector = cvss_data['cvssData'].get('vectorString', 'N/A')
                    
                    # Get references
                    references = []
                    if 'references' in cve:
                        for ref in cve['references']:
                            ref_url = ref.get('url', '')
                            if ref_url:
                                references.append(ref_url)
                    
                    # Create the document
                    doc_content = (f"CVE ID: {cve_id}\n"
                                   f"Severity: {severity}\n"
                                   f"Base Score: {base_score}\n"
                                   f"Vector: {vector}\n"
                                   f"Description: {description}\n"
                                   f"References: {', '.join(references[:3])}")
                    
                    documents.append(Document(
                        page_content=doc_content,
                        metadata={
                            "source": "nvd",
                            "cve_id": cve_id,
                            "severity": severity,
                            "base_score": base_score,
                            "vector": vector,
                            "cvss_version": cvss_version if cvss_data else "N/A",
                            "references": references[:3],  # Store first 3 references in metadata
                            "published_date": cve.get('published', 'Unknown'),
                            "last_modified": cve.get('lastModified', 'Unknown'),
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        }
                    ))
                except Exception as e:
                    # Skip this vulnerability but log the error
                    st.warning(f"Error processing vulnerability: {str(e)}")
                    continue
            
            # Add to vector database
            if documents:
                try:
                    db = Chroma(persist_directory=persistent_directory, embedding_function=embeddings)
                    db.add_documents(documents)
                    db.persist()
                except Exception as e:
                    st.error(f"Error storing vulnerabilities in vector database: {str(e)}")
            
            return vulnerabilities, None
        else:
            return [], f"API returned status code {response.status_code}: {response.text}"
    except requests.exceptions.Timeout:
        return [], "Request to NVD API timed out. Please try again later."
    except requests.exceptions.ConnectionError:
        return [], "Connection error. Please check your internet connection."
    except Exception as e:
        return [], f"Error fetching vulnerabilities: {str(e)}"

def filter_vulnerabilities(vulnerabilities, severity_filter="all"):
    """Filter vulnerabilities based on severity"""
    if severity_filter == "all":
        return vulnerabilities
    
    filtered = []
    for vuln in vulnerabilities:
        try:
            cve = vuln.get('cve', {})
            metrics = cve.get('metrics', {})
            
            # Try to find severity in CVSS v3.1, v3.0 or v2.0 data
            severity = None
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                severity = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseSeverity')
            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                severity = metrics['cvssMetricV30'][0].get('cvssData', {}).get('baseSeverity')
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                # For CVSS v2, map the score to a severity
                base_score = metrics['cvssMetricV2'][0].get('cvssData', {}).get('baseScore')
                if base_score is not None:
                    if base_score >= 7.0:
                        severity = "HIGH"
                    elif base_score >= 4.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"
            
            # Apply filter
            if severity:
                if severity_filter == "critical" and severity == "CRITICAL":
                    filtered.append(vuln)
                elif severity_filter == "high" and (severity == "HIGH" or severity == "CRITICAL"):
                    filtered.append(vuln)
                elif severity_filter == "medium" and severity == "MEDIUM":
                    filtered.append(vuln)
                elif severity_filter == "low" and severity == "LOW":
                    filtered.append(vuln)
        except Exception:
            # Skip vulnerabilities that can't be properly assessed
            continue
    
    return filtered

def setup_rag_chain():
    """Set up the RAG chain for vulnerability analysis"""
    llm = get_llm()
    if llm is None:
        return None
    
    try:
        db = Chroma(persist_directory=persistent_directory, embedding_function=embeddings)
        
        # Create a retriever
        retriever = db.as_retriever(
            search_type="similarity",
            search_kwargs={"k": 7},
        )
        
        # Contextualize question prompt
        contextualize_q_system_prompt = (
            "Given a chat history and the latest user question "
            "which might reference context in the chat history, "
            "formulate a standalone question which can be understood "
            "without the chat history. Do NOT answer the question, just "
            "reformulate it if needed and otherwise return it as is."
        )
        
        contextualize_q_prompt = ChatPromptTemplate.from_messages(
            [
                ("system", contextualize_q_system_prompt),
                MessagesPlaceholder("chat_history"),
                ("human", "{input}"),
            ]
        )
        
        # Create a history-aware retriever
        history_aware_retriever = create_history_aware_retriever(
            llm, retriever, contextualize_q_prompt
        )
        
        # Answer question prompt
        qa_system_prompt = (
            "You are SecurityAI, an expert cybersecurity analyst specializing in vulnerability assessment, threat analysis, and mitigation strategies. "
            "Use the following pieces of retrieved context to analyze vulnerabilities and their applicability "
            "to the user's system. When asked about vulnerabilities:"
            "\n\n"
            "1. Identify if the vulnerability applies to the user's system configuration based on OS, software, and hardware details"
            "2. Provide detailed but concise mitigation steps specific to the user's system"
            "3. Explain the severity and potential impact of the vulnerability in practical terms"
            "4. Include specific commands or configuration changes the user should implement"
            "5. Reference any official advisories or patches available"
            "\n\n"
            "If you don't have enough information, ask for specific details about the system. "
            "If a vulnerability likely doesn't apply to the user's system, explain why while noting any uncertainty."
            "\n\n"
            "{context}"
        )
        
        qa_prompt = ChatPromptTemplate.from_messages(
            [
                ("system", qa_system_prompt),
                MessagesPlaceholder("chat_history"),
                ("human", "{input}"),
            ]
        )
        
        # Create a chain to combine documents for question answering
        question_answer_chain = create_stuff_documents_chain(llm, qa_prompt)
        
        # Create the full retrieval chain
        rag_chain = create_retrieval_chain(history_aware_retriever, question_answer_chain)
        
        return rag_chain
    except Exception as e:
        st.error(f"Error setting up RAG chain: {str(e)}")
        return None

def display_vulnerability_chat(vuln_key, vulnerability, system_info):
    """Display a chat interface for a specific vulnerability"""
    st.subheader(f"Security Assistant for {vulnerability.get('cve', {}).get('id', 'this vulnerability')}")
    
    # Get description for context
    description = "No description available"
    for desc in vulnerability.get('cve', {}).get('descriptions', []):
        if desc.get('lang') == 'en':
            description = desc.get('value', 'No description available')
            break
            
    # Initialize chat history for this vulnerability if not exists
    if vuln_key not in st.session_state.vulnerability_chats:
        st.session_state.vulnerability_chats[vuln_key] = []
    
    # Display chat history for this vulnerability
    for message in st.session_state.vulnerability_chats[vuln_key]:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
    
    # Chat input for this vulnerability - use a consistent key
    vuln_prompt = st.chat_input(f"Ask about {vulnerability.get('cve', {}).get('id', 'this vulnerability')}...", key=f"chat_input_{vuln_key}")
    
    if vuln_prompt:
        # Add user message to chat history
        st.session_state.vulnerability_chats[vuln_key].append({"role": "user", "content": vuln_prompt})
        
        # Display user message
        with st.chat_message("user"):
            st.markdown(vuln_prompt)
        
        # Generate response
        with st.spinner("Analyzing..."):
            try:
                rag_chain = setup_rag_chain()
                if rag_chain:
                    # Convert the chat history to the format expected by the chain
                    chain_chat_history = [
                        HumanMessage(content=msg["content"]) if msg["role"] == "user" 
                        else AIMessage(content=msg["content"])
                        for msg in st.session_state.vulnerability_chats[vuln_key][:-1]  # Exclude the latest user message
                    ]
                    
                    # Create a context-aware prompt including vulnerability details
                    context_prompt = f"You are discussing CVE {vulnerability.get('cve', {}).get('id', 'Unknown')}. "
                    context_prompt += f"Description: {description}. "
                    context_prompt += f"Operating System: {system_info['os']['name']} {system_info['os']['version']}. "
                    context_prompt += f"User's question: {vuln_prompt}"
                    
                    result = rag_chain.invoke({
                        "input": context_prompt,
                        "chat_history": chain_chat_history
                    })
                    
                    response = result['answer']
                else:
                    response = "I'm unable to generate a response at the moment. Please check your API keys in the .env file."
            except Exception as e:
                response = f"I encountered an error: {str(e)}. Please try again."
            
            # Add assistant response to chat history
            st.session_state.vulnerability_chats[vuln_key].append({"role": "assistant", "content": response})
            
            # Display assistant response
            with st.chat_message("assistant"):
                st.markdown(response)
        
        # Remove this line that was causing the interface to collapse
        # st.session_state[f"vuln_chat_active_{vuln_key}"] = True

def generate_vulnerability_report(vulnerability, system_info, mitigation_steps):
    """Generate a detailed vulnerability report with better markdown formatting"""
    try:
        # Extract vulnerability details
        cve = vulnerability.get('cve', {})
        cve_id = cve.get('id', 'Unknown')
        
        # Find English description
        description = "No description available"
        for desc in cve.get('descriptions', []):
            if desc.get('lang') == 'en':
                description = desc.get('value', 'No description available')
                break
        
        # Extract metrics
        metrics = cve.get('metrics', {})
        cvss_data = None
        cvss_version = "N/A"
        
        # Try to get CVSS v3.1 data first, then v3.0, then v2.0
        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            cvss_data = metrics['cvssMetricV31'][0]
            cvss_version = "3.1"
        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            cvss_data = metrics['cvssMetricV30'][0]
            cvss_version = "3.0"
        elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
            cvss_data = metrics['cvssMetricV2'][0]
            cvss_version = "2.0"
        
        base_score = "N/A"
        severity = "N/A"
        vector = "N/A"
        
        if cvss_data and 'cvssData' in cvss_data:
            base_score = cvss_data['cvssData'].get('baseScore', 'N/A')
            severity = cvss_data['cvssData'].get('baseSeverity', 'N/A')
            vector = cvss_data['cvssData'].get('vectorString', 'N/A')
        
        # Get references
        references = []
        if 'references' in cve:
            for ref in cve['references']:
                ref_url = ref.get('url', '')
                ref_tags = ref.get('tags', [])
                if ref_url:
                    references.append({
                        "url": ref_url,
                        "tags": ref_tags
                    })
        
        # Determine severity class for styling
        severity_class = "na"
        if severity == "CRITICAL":
            severity_class = "critical"
        elif severity == "HIGH":
            severity_class = "high"
        elif severity == "MEDIUM":
            severity_class = "medium"
        elif severity == "LOW":
            severity_class = "low"
        
        # Get published date and format it
        published_date = cve.get('published', 'Unknown')
        if published_date != 'Unknown':
            try:
                published_date = datetime.fromisoformat(published_date.replace('Z', '+00:00')).strftime("%Y-%m-%d")
            except:
                pass
        
        # Format the mitigation steps for better markdown rendering
        # Convert markdown headings, lists, and emphasized text to HTML
        formatted_mitigation = mitigation_steps
        
        # Replace markdown headings with HTML headings
        formatted_mitigation = formatted_mitigation.replace('**', '<strong>', 1)
        while '**' in formatted_mitigation:
            formatted_mitigation = formatted_mitigation.replace('**', '</strong>', 1)
            if '**' in formatted_mitigation:
                formatted_mitigation = formatted_mitigation.replace('**', '<strong>', 1)
        
        # Handle numbered lists
        lines = formatted_mitigation.split('\n')
        in_list = False
        list_type = None
        formatted_lines = []
        
        for line in lines:
            # Check for numbered list items
            if re.match(r'^\d+\.\s', line):
                if not in_list or list_type != 'ol':
                    if in_list:
                        formatted_lines.append(f"</{list_type}>")
                    formatted_lines.append("<ol>")
                    in_list = True
                    list_type = 'ol'
                formatted_lines.append(f"<li>{line.split('. ', 1)[1]}</li>")
            # Check for bullet list items
            elif line.strip().startswith('* ') or line.strip().startswith('- '):
                if not in_list or list_type != 'ul':
                    if in_list:
                        formatted_lines.append(f"</{list_type}>")
                    formatted_lines.append("<ul>")
                    in_list = True
                    list_type = 'ul'
                formatted_lines.append(f"<li>{line.strip()[2:]}</li>")
            else:
                if in_list:
                    formatted_lines.append(f"</{list_type}>")
                    in_list = False
                    list_type = None
                formatted_lines.append(line)
        
        if in_list:
            formatted_lines.append(f"</{list_type}>")
        
        formatted_mitigation = '<br>'.join(formatted_lines)
        
        # Enhanced HTML report with proper markdown parsing
        report = f"""
        <div class="report-container" style="font-family: 'Helvetica Neue', Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; color: #333;">
            <h1 style="color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;">Vulnerability Assessment Report</h1>
            <div class="section-{severity_class}" style="background-color: #f8f9fa; border-left: 5px solid #{'#e74c3c' if severity_class == 'critical' or severity_class == 'high' else '#f39c12' if severity_class == 'medium' else '#3498db' if severity_class == 'low' else '#95a5a6'}; padding: 15px; margin-bottom: 20px; border-radius: 4px;">
                <h2 style="color: #2c3e50; margin-top: 0;">Vulnerability Details</h2>
                <p><strong>CVE ID:</strong> {cve_id}</p>
                <p><strong>Severity:</strong> <span style="color: {'#e74c3c' if severity_class == 'critical' or severity_class == 'high' else '#f39c12' if severity_class == 'medium' else '#3498db' if severity_class == 'low' else '#95a5a6'}; font-weight: bold;">{severity}</span></p>
                <p><strong>Base Score:</strong> {base_score} (CVSS v{cvss_version})</p>
                <p><strong>Vector:</strong> {vector}</p>
                <p><strong>Published:</strong> {published_date}</p>
                <p><strong>Description:</strong> {description}</p>
            </div>
            
            <div class="section" style="background-color: #f8f9fa; padding: 15px; margin-bottom: 20px; border-radius: 4px;">
                <h2 style="color: #2c3e50; margin-top: 0;">System Information</h2>
                <p><strong>Operating System:</strong> {system_info['os']['name']} {system_info['os']['version']} ({system_info['os']['architecture']})</p>
                <p><strong>Distribution:</strong> {system_info['os']['distribution']}</p>
                <p><strong>Processor:</strong> {system_info['hardware']['processor']}</p>
                <p><strong>Assessment Date:</strong> {datetime.now().strftime("%Y-%m-%d")}</p>
            </div>
            
            <div class="section mitigation" style="background-color: #f8f9fa; padding: 15px; margin-bottom: 20px; border-radius: 4px;">
                <h2 style="color: #2c3e50; margin-top: 0;">Mitigation Steps</h2>
                <div style="line-height: 1.6;">{formatted_mitigation}</div>
            </div>
            
            <div class="references" style="background-color: #f8f9fa; padding: 15px; margin-bottom: 20px; border-radius: 4px;">
                <h2 style="color: #2c3e50; margin-top: 0;">References</h2>
                <ul style="padding-left: 20px;">
        """
        
        # Add references to the report
        for ref in references[:5]:  # Limit to first 5 references
            report += f'<li><a href="{ref["url"]}" target="_blank" style="color: #3498db; text-decoration: none;">{ref["url"]}</a></li>'
        
        report += """
                </ul>
            </div>
            
            <div class="footer" style="text-align: center; margin-top: 30px; font-size: 0.8em; color: #7f8c8d; border-top: 1px solid #ecf0f1; padding-top: 10px;">
                <p>Generated by PatchWise OS Vulnerability Assessment Tool on {}</p>
            </div>
        </div>
        """.format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        return report
    except Exception as e:
        return f"<div class='error' style='color: #e74c3c; padding: 15px; border: 1px solid #e74c3c; border-radius: 4px;'>Error generating report: {str(e)}</div>"

def count_vulnerabilities_by_severity(vulnerabilities):
    """Count vulnerabilities by severity level"""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    
    for vuln in vulnerabilities:
        try:
            cve = vuln.get('cve', {})
            metrics = cve.get('metrics', {})
            
            severity = None
            # Try to find severity in CVSS v3.1, v3.0 or v2.0 data
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                severity = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseSeverity')
            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                severity = metrics['cvssMetricV30'][0].get('cvssData', {}).get('baseSeverity')
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                # For CVSS v2, map the score to a severity
                base_score = metrics['cvssMetricV2'][0].get('cvssData', {}).get('baseScore')
                if base_score is not None:
                    if base_score >= 9.0:
                        severity = "CRITICAL"
                    elif base_score >= 7.0:
                        severity = "HIGH"
                    elif base_score >= 4.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"
            
            if severity in counts:
                counts[severity] += 1
            else:
                counts["UNKNOWN"] += 1
        except Exception:
            counts["UNKNOWN"] += 1
    
    return counts

def display_system_info():
    """Display system information in Streamlit"""
    if st.session_state.system_info:
        sys_info = st.session_state.system_info
        
        # Create system info card wrapper
        st.markdown('<div class="card">', unsafe_allow_html=True)
        
        # Create a layout with columns
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Operating System")
            os_info = (
                f"**Name:** {sys_info['os']['name']}\n\n"
                f"**Version:** {sys_info['os']['version']}\n\n"
                f"**Release:** {sys_info['os']['release']}\n\n"
                f"**Architecture:** {sys_info['os']['architecture']}"
            )
            st.markdown(os_info)
            
            # Display disk usage if available
            if 'disk_usage' in sys_info['hardware']:
                st.subheader("Disk Usage")
                total_gb = sys_info['hardware']['disk_usage']['total'] / (1024**3)
                used_gb = sys_info['hardware']['disk_usage']['used'] / (1024**3)
                free_gb = sys_info['hardware']['disk_usage']['free'] / (1024**3)
                
                # Create a gauge chart for disk usage with modern styling
                fig = go.Figure(go.Indicator(
                    mode = "gauge+number",
                    value = sys_info['hardware']['disk_usage']['percent'],
                    title = {'text': "Disk Usage (%)"},
                    domain = {'x': [0, 1], 'y': [0, 1]},
                    gauge = {
                        'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "#FFFFFF"},
                        'bar': {'color': "#4361ee"},
                        'bgcolor': "white",
                        'borderwidth': 2,
                        'bordercolor': "white",
                        'steps': [
                            {'range': [0, 50], 'color': "#4cc9f0"},
                            {'range': [50, 75], 'color': "#fca311"},
                            {'range': [75, 100], 'color': "#e63946"}
                        ]
                    }
                ))
                fig.update_layout(
                    height=200, 
                    margin=dict(l=10, r=10, t=50, b=10),
                    paper_bgcolor="rgba(0,0,0,0)",
                    font={'color': "#333333", 'family': "Inter, Arial, sans-serif"}
                )
                st.plotly_chart(fig, use_container_width=True)
                
                st.markdown(f"**Total:** {total_gb:.1f} GB\n\n**Used:** {used_gb:.1f} GB\n\n**Free:** {free_gb:.1f} GB")
        
        with col2:
            st.subheader("Hardware")
            hw_info = (
                f"**Processor:** {sys_info['hardware']['processor']}\n\n"
                f"**Physical Cores:** {sys_info['hardware']['physical_cores']}\n\n"
                f"**Total Cores:** {sys_info['hardware']['total_cores']}\n\n"
                f"**Memory Total:** {sys_info['hardware']['memory_total'] // (1024**3)} GB\n\n"
                f"**Memory Available:** {sys_info['hardware']['memory_available'] // (1024**3)} GB"
            )
            st.markdown(hw_info)
            
            # Memory usage visualization with modern styling
            memory_total = sys_info['hardware']['memory_total']
            memory_available = sys_info['hardware']['memory_available']
            memory_used = memory_total - memory_available
            
            memory_percent = (memory_used / memory_total) * 100 if memory_total > 0 else 0
            
            # Create a gauge chart for memory usage
            fig = go.Figure(go.Indicator(
                mode = "gauge+number",
                value = memory_percent,
                title = {'text': "Memory Usage (%)"},
                domain = {'x': [0, 1], 'y': [0, 1]},
                gauge = {
                    'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "#FFFFFF"},
                    'bar': {'color': "#4361ee"},
                    'bgcolor': "white",
                    'borderwidth': 2,
                    'bordercolor': "white",
                    'steps': [
                        {'range': [0, 50], 'color': "#4cc9f0"},
                        {'range': [50, 75], 'color': "#fca311"},
                        {'range': [75, 100], 'color': "#e63946"}
                    ]
                }
            ))
            fig.update_layout(
                height=200, 
                margin=dict(l=10, r=10, t=50, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                font={'color': "#333333", 'family': "Inter, Arial, sans-serif"}
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Close the system info card
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Display installed packages in an expandable section with card styling
        with st.expander("Installed Packages"):
            if "installed_packages" in sys_info["software"] and isinstance(sys_info["software"]["installed_packages"], list):
                # Create a DataFrame for better display
                packages_data = [
                    {"Package": pkg.get("name", "Unknown"), "Version": pkg.get("version", "Unknown")}
                    for pkg in sys_info["software"]["installed_packages"]
                ]
                
                if packages_data:
                    df = pd.DataFrame(packages_data)
                    st.dataframe(df, use_container_width=True)
                else:
                    st.info("No package information available")
            else:
                st.info("Package information not available")
        
        # Display network interfaces with card styling
        with st.expander("Network Interfaces"):
            if "network" in sys_info and "interfaces" in sys_info["network"]:
                for interface in sys_info["network"]["interfaces"]:
                    st.markdown(f'<div class="card">', unsafe_allow_html=True)
                    st.markdown(f"**Interface:** {interface.get('name', 'Unknown')}")
                    if "mac" in interface:
                        st.markdown(f"**MAC Address:** {interface['mac']}")
                    
                    if "addresses" in interface:
                        for addr in interface["addresses"]:
                            st.markdown(f"- **{addr.get('family', 'IP')}:** {addr.get('ip', 'Unknown')}")
                            if addr.get('netmask'):
                                st.markdown(f"  **Netmask:** {addr['netmask']}")
                    st.markdown('</div>', unsafe_allow_html=True)
            else:
                st.info("Network information not available")

def display_vulnerability_metrics(vulnerabilities):
    """Display vulnerability metrics using Plotly charts"""
    # Count vulnerabilities by severity
    counts = count_vulnerabilities_by_severity(vulnerabilities)
    
    # Create a pie chart for severity distribution
    severity_data = []
    for severity, count in counts.items():
        if count > 0:  # Only add non-zero counts
            severity_data.append({"Severity": severity, "Count": count})
    
    if severity_data:
        df = pd.DataFrame(severity_data)
        
        # Define modern colors for each severity level
        colors = {
            "CRITICAL": "#e63946", 
            "HIGH": "#f94144",
            "MEDIUM": "#fca311",
            "LOW": "#2a9d8f",
            "UNKNOWN": "#6c757d"
        }
        
        # Create the pie chart with modern styling
        fig = px.pie(
            df, 
            names="Severity", 
            values="Count",
            color="Severity",
            color_discrete_map=colors,
            title="Vulnerabilities by Severity"
        )
        fig.update_traces(
            textposition='inside', 
            textinfo='percent+label',
            hoverinfo='label+percent+value',
            marker=dict(line=dict(color='#FFFFFF', width=2))
        )
        fig.update_layout(
            margin=dict(t=50, b=20, l=10, r=10),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font={'family': "Inter, Arial, sans-serif", 'size': 12},
            title={'font': {'size': 16, 'family': "Inter, Arial, sans-serif", 'color': "#333333"}},
            legend={'font': {'size': 12}}
        )
        
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.info("No vulnerability data available for visualization")

def main():
    # App title and description
    st.title("PatchWise: OS Vulnerability Remediation System")
    st.markdown("""
    <div class="card">
    <h3>Welcome to PatchWise!</h3>
    <p>I will scan your system for latest vulnerabilities released by NVD
    and provide detailed remediation using AI-powered analysis.</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Display error message if any
    if st.session_state.error_message:
        st.error(st.session_state.error_message)
        if st.button("Clear Error"):
            st.session_state.error_message = None
            st.rerun()
    
    # Main content tabs
    tab1, tab2, tab3, tab4 = st.tabs(["🔎 Scan", "📊 Dashboard", "🔍 Vulnerabilities", "🤖 Security Assistant"])
    
    with tab2:
        st.header("System Overview")
        
        if st.session_state.system_info:
            display_system_info()
        else:
            st.markdown('<div class="card"><p>No system information available. Please run a scan first.</p></div>', unsafe_allow_html=True)
        
        st.header("Vulnerability Summary")
        
        if st.session_state.vulnerabilities:
            # Display metrics
            display_vulnerability_metrics(st.session_state.vulnerabilities)
            
            # Vulnerability counts by severity
            counts = count_vulnerabilities_by_severity(st.session_state.vulnerabilities)
            
            st.markdown('<div class="card">', unsafe_allow_html=True)
            # Display metrics in columns
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric(
                    label="Critical", 
                    value=counts["CRITICAL"],
                    delta=None
                )
            with col2:
                st.metric(
                    label="High", 
                    value=counts["HIGH"],
                    delta=None
                )
            with col3:
                st.metric(
                    label="Medium", 
                    value=counts["MEDIUM"],
                    delta=None
                )
            with col4:
                st.metric(
                    label="Low", 
                    value=counts["LOW"],
                    delta=None
                )
            
            # Add total count
            st.metric(
                label="Total vulnerabilities found", 
                value=sum(counts.values()),
                delta=None
            )
            st.markdown('</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="card"><p>No vulnerabilities detected. Run a scan to check for issues.</p></div>', unsafe_allow_html=True)
    
    with tab3:
        st.header("Detected Vulnerabilities")
        
        if not st.session_state.vulnerabilities:
            st.info("No vulnerabilities detected. Run a scan to check for issues.")
        else:
            # Filtering options
            col1, col2 = st.columns([3, 1])
            with col1:
                # Search box
                search_term = st.text_input("Search vulnerabilities", "")
            with col2:
                # Severity filter dropdown
                severity_options = ["All", "Critical Only", "High & Critical", "Medium & Above", "Low & Above"]
                severity_select = st.selectbox("Filter by severity", severity_options, index=0)
            
            # Apply filters
            displayed_vulns = st.session_state.filtered_vulnerabilities
            
            # Apply severity filter based on dropdown
            if severity_select == "Critical Only":
                displayed_vulns = filter_vulnerabilities(displayed_vulns, "critical")
            elif severity_select == "High & Critical":
                displayed_vulns = filter_vulnerabilities(displayed_vulns, "high")
            elif severity_select == "Medium & Above":
                displayed_vulns = filter_vulnerabilities(displayed_vulns, "medium")
            elif severity_select == "Low & Above":
                displayed_vulns = filter_vulnerabilities(displayed_vulns, "low")
            
            # Apply search filter if search term is provided
            if search_term:
                search_term = search_term.lower()
                filtered_vulns = []
                for vuln in displayed_vulns:
                    cve = vuln.get('cve', {})
                    cve_id = cve.get('id', '').lower()
                    
                    # Search in descriptions
                    desc_match = False
                    for desc in cve.get('descriptions', []):
                        if search_term in desc.get('value', '').lower():
                            desc_match = True
                            break
                    
                    if search_term in cve_id or desc_match:
                        filtered_vulns.append(vuln)
                displayed_vulns = filtered_vulns
            
            # Display vulnerabilities or show message if none match filters
            if not displayed_vulns:
                st.warning("No vulnerabilities match your filter criteria.")
            else:
                st.write(f"Displaying {len(displayed_vulns)} vulnerabilities:")
                
                # Sort vulnerabilities by severity
                def get_severity_score(vuln):
                    cve = vuln.get('cve', {})
                    metrics = cve.get('metrics', {})
                    
                    # Try to find base score in CVSS v3.1, v3.0 or v2.0 data
                    base_score = 0
                    if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                        base_score = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseScore', 0) or 0
                    elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                        base_score = metrics['cvssMetricV30'][0].get('cvssData', {}).get('baseScore', 0) or 0
                    elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                        base_score = metrics['cvssMetricV2'][0].get('cvssData', {}).get('baseScore', 0) or 0
                    return float(base_score) if isinstance(base_score, (int, float)) else 0
                
                displayed_vulns = sorted(displayed_vulns, key=get_severity_score, reverse=True)
                
                # Display vulnerabilities
                for idx, vuln in enumerate(displayed_vulns):
                    # Extract CVE details
                    cve = vuln.get('cve', {})
                    cve_id = cve.get('id', 'Unknown')
                    
                    # Get metrics and severity
                    metrics = cve.get('metrics', {})
                    cvss_data = None
                    severity = "N/A"
                    base_score = "N/A"
                    
                    # Try to get CVSS v3.1 data first, then v3.0, then v2.0
                    if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                        cvss_data = metrics['cvssMetricV31'][0]
                        cvss_version = "v3.1"
                    elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                        cvss_data = metrics['cvssMetricV30'][0]
                        cvss_version = "v3.0"
                    elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                        cvss_data = metrics['cvssMetricV2'][0]
                        cvss_version = "v2.0"
                    else:
                        cvss_version = "N/A"
                    
                    if cvss_data and 'cvssData' in cvss_data:
                        severity = cvss_data['cvssData'].get('baseSeverity', 'N/A')
                        base_score = cvss_data['cvssData'].get('baseScore', 'N/A')
                    
                    # Determine CSS class based on severity
                    severity_class = "low"
                    if severity == "CRITICAL":
                        severity_class = "high"
                    elif severity == "HIGH":
                        severity_class = "high"
                    elif severity == "MEDIUM":
                        severity_class = "medium"
                    
                    # Get description
                    description = "No description available"
                    for desc in cve.get('descriptions', []):
                        if desc.get('lang') == 'en':
                            description = desc.get('value', 'No description available')
                            break
                    
                    # Truncate description if too long
                    short_description = description[:200] + "..." if len(description) > 200 else description
                    
                    # Create a custom HTML component for each vulnerability
                    st.markdown(f"""
                    <div class="vulnerability-{severity_class}">
                        <h3>{cve_id} - {severity} ({base_score} CVSS {cvss_version})</h3>
                        <p>{short_description}</p>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Create columns for buttons
                    col1, col2 = st.columns([1, 4])
                    
                    with col1:
                        # Button to view full details
                        if st.button(f"View Details", key=f"view_{idx}"):
                            with st.expander(f"Details for {cve_id}", expanded=True):
                                st.markdown(f"**Severity:** {severity}")
                                st.markdown(f"**Base Score:** {base_score}")
                                st.markdown(f"**Description:**")
                                st.markdown(description)
                                
                                # Show references if available
                                if 'references' in cve and cve['references']:
                                    st.markdown("**References:**")
                                    for ref in cve['references'][:5]:  # Limit to first 5 references
                                        ref_url = ref.get('url', '')
                                        if ref_url:
                                            st.markdown(f"- [{ref_url}]({ref_url})")
                    
                    with col2:
                        # Button to generate mitigation report
                        if st.button(f"Generate Mitigation", key=f"gen_{idx}"):
                            with st.spinner("Analyzing vulnerability..."):
                                try:
                                    rag_chain = setup_rag_chain()
                                    if rag_chain:
                                        # Generate a unique key for this vulnerability
                                        vuln_key = f"vuln_{cve_id}_{idx}"
                                        
                                        # Initialize chat history for this vulnerability if not exists
                                        if vuln_key not in st.session_state.vulnerability_chats:
                                            # First analyze the vulnerability to get mitigation steps
                                            result = rag_chain.invoke({
                                                "input": f"Analyze vulnerability {cve_id} with description: {description}. What are the specific mitigation steps for this vulnerability on {st.session_state.system_info['os']['name']} systems?",
                                                "chat_history": []
                                            })
                                            
                                            # Save the initial analysis to chat history
                                            initial_response = f"Here's my analysis of **{cve_id}**:\n\n{result['answer']}\n\nYou can ask me followup questions about this vulnerability."
                                            st.session_state.vulnerability_chats[vuln_key] = [
                                                {"role": "assistant", "content": initial_response}
                                            ]
                                            
                                            # Generate HTML report
                                            report_html = generate_vulnerability_report(
                                                vuln, 
                                                st.session_state.system_info, 
                                                result['answer']
                                            )
                                            
                                            # Store report HTML in session state
                                            st.session_state[f"report_{vuln_key}"] = report_html
                                        
                                        # Create a container for the chat and report UI
                                        vuln_container = st.container()
                                        
                                        with vuln_container:
                                            col1, col2 = st.columns([3, 1])
                                            
                                            with col2:
                                                # Add option to download report
                                                if f"report_{vuln_key}" in st.session_state:
                                                    st.download_button(
                                                        label="📥 Download Report",
                                                        data=st.session_state[f"report_{vuln_key}"],
                                                        file_name=f"{cve_id}_report.html",
                                                        mime="text/html",
                                                        key=f"download_{vuln_key}"
                                                    )
                                                    
                                                    # Option to view full report
                                                    if st.button("👁️ View Full Report", key=f"view_report_{vuln_key}"):
                                                        st.markdown(st.session_state[f"report_{vuln_key}"], unsafe_allow_html=True)
                                            
                                            with col1:
                                                # Display the chat interface for this vulnerability
                                                display_vulnerability_chat(vuln_key, vuln, st.session_state.system_info)
                                    else:
                                        st.error("Unable to generate report. Please check your API keys.")
                                except Exception as e:
                                    st.error(f"Analysis failed: {str(e)}")
                    
                    st.markdown("---")
    
    with tab4:
        st.header("Security Assistant")
        st.markdown("""
        Our AI security assistant can help answer your security questions and provide 
        personalized advice based on your system configuration.
        """)
        
        # Add text-to-speech toggle
        tts_enabled = st.toggle(
            "Enable text-to-speech",
            value=st.session_state.settings.get("text_to_speech", False),
            help="Enable voice responses from the assistant"
        )
        
        # Update settings if changed
        if tts_enabled != st.session_state.settings.get("text_to_speech", False):
            st.session_state.settings["text_to_speech"] = tts_enabled
        
        # Create a container for the chat interface
        chat_container = st.container()
        
        with chat_container:
            # Initialize chat history if empty
            if "chat_history" not in st.session_state:
                st.session_state.chat_history = []
            
            # Display chat history
            for message in st.session_state.chat_history:
                with st.chat_message(message["role"]):
                    st.markdown(message["content"])
        
        # Chat input - positioned at the bottom of the interface
        prompt = st.chat_input("Ask a security question...")
        
        if prompt:
            # Add user message to chat history
            st.session_state.chat_history.append({"role": "user", "content": prompt})
            
            # Display user message
            with st.chat_message("user"):
                st.markdown(prompt)
            
            # Generate response
            with st.spinner("Thinking..."):
                try:
                    if not st.session_state.system_info:
                        # If no system scan yet, prompt the user to run a scan
                        response = "I don't have information about your system yet. Please run a system scan first by clicking the 'Scan System' button in the sidebar."
                    else:
                        # Generate response using RAG chain
                        rag_chain = setup_rag_chain()
                        if rag_chain:
                            # Convert the chat history to the format expected by the chain
                            chain_chat_history = [
                                HumanMessage(content=msg["content"]) if msg["role"] == "user" 
                                else AIMessage(content=msg["content"])
                                for msg in st.session_state.chat_history[:-1]  # Exclude the latest user message
                            ]
                            
                            result = rag_chain.invoke({
                                "input": prompt,
                                "chat_history": chain_chat_history
                            })
                            
                            response = result['answer']
                        else:
                            response = "I'm unable to generate a response at the moment. Please check your API keys in the .env file."
                except Exception as e:
                    response = f"I encountered an error: {str(e)}. Please try again or check your configuration."
                
                # Add assistant response to chat history
                st.session_state.chat_history.append({"role": "assistant", "content": response})
                
                # Display assistant response
                with st.chat_message("assistant"):
                    st.markdown(response)
                    
                    # Generate speech if enabled
                    if st.session_state.settings.get("text_to_speech", False):
                        # Create a simpler version of the response for speech
                        # Remove markdown formatting and simplify for better TTS
                        speech_text = response
                        speech_text = re.sub(r'\*\*(.*?)\*\*', r'\1', speech_text)  # Remove bold
                        speech_text = re.sub(r'\*(.*?)\*', r'\1', speech_text)      # Remove italic
                        speech_text = re.sub(r'\[(.*?)\]\(.*?\)', r'\1', speech_text)  # Remove links
                        speech_text = re.sub(r'`(.*?)`', r'\1', speech_text)        # Remove code
                        speech_text = re.sub(r'```.*?```', '', speech_text, flags=re.DOTALL)  # Remove code blocks
                        
                        # Truncate text if too long to avoid TTS limits
                        if len(speech_text) > 3000:
                            speech_text = speech_text[:3000] + "... Response truncated for speech."
                        
                        # Generate TTS and display audio element
                        # Define a simple text_to_speech function
                        def text_to_speech(text):
                            try:
                                tts = gTTS(text=text, lang='en')
                                audio_buffer = BytesIO()
                                tts.write_to_fp(audio_buffer)
                                audio_buffer.seek(0)
                                audio_base64 = base64.b64encode(audio_buffer.read()).decode()
                                return f'<audio controls><source src="data:audio/mpeg;base64,{audio_base64}" type="audio/mpeg"></audio>'
                            except Exception as e:
                                st.error(f"Error generating speech: {str(e)}")
                                return None

                        audio_html = text_to_speech(speech_text)
                        if audio_html:
                            st.markdown(audio_html, unsafe_allow_html=True)
    
    with tab1:
        st.header("System Scan")
        
        # Scan system section
        st.markdown("""
        Scan your system to detect potential vulnerabilities and security issues.
        The scan will collect information about your operating system, hardware, and installed packages.
        """)
        
        # Scan system button
        if st.button("🔍 Scan System", type="primary"):
            with st.spinner("Scanning your system and checking for vulnerabilities..."):
                st.session_state.scan_status["in_progress"] = True
                
                # Store system information
                num_docs, error = store_system_info()
                if error:
                    st.session_state.error_message = f"Error scanning system: {error}"
                else:
                    # Fetch vulnerabilities
                    vulnerabilities, error = fetch_vulnerabilities()
                    if error:
                        st.session_state.error_message = error
                    else:
                        st.session_state.vulnerabilities = vulnerabilities
                        st.session_state.filtered_vulnerabilities = filter_vulnerabilities(
                            vulnerabilities, st.session_state.settings["severity_filter"])
                        st.session_state.scan_status["last_scan"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        st.success(f"Scan complete! Found {len(vulnerabilities)} potential vulnerabilities.")
                
                st.session_state.scan_status["in_progress"] = False
                st.rerun()  # Refresh the UI
        
        # Display last scan time
        if st.session_state.scan_status["last_scan"]:
            st.info(f"Last scan: {st.session_state.scan_status['last_scan']}")
        
        # Settings section
        st.subheader("Settings")
        
        # LLM provider information
        st.info("Using Google Gemini for AI analysis")
        
        # Severity filter
        severity_filter = st.selectbox(
            "Severity Filter",
            options=["all", "critical", "high", "medium", "low"],
            index=["all", "critical", "high", "medium", "low"].index(st.session_state.settings["severity_filter"]),
            help="Filter vulnerabilities by severity level."
        )
        
        # Days to fetch
        days_to_fetch = st.slider(
            "Days to look back",
            min_value=1,
            max_value=30,
            value=st.session_state.settings["days_to_fetch"],
            help="Number of days to look back for vulnerabilities."
        )
        
        # Text-to-speech settings in the Settings tab as well
        tts_setting = st.checkbox(
            "Enable text-to-speech for assistant",
            value=st.session_state.settings.get("text_to_speech", False),
            help="Enable voice responses from the security assistant"
        )
        
        # Update settings
        if (severity_filter != st.session_state.settings["severity_filter"] or
            days_to_fetch != st.session_state.settings["days_to_fetch"] or
            tts_setting != st.session_state.settings.get("text_to_speech", False)):
            
            st.session_state.settings["llm_provider"] = "google"
            st.session_state.settings["severity_filter"] = severity_filter
            st.session_state.settings["days_to_fetch"] = days_to_fetch
            st.session_state.settings["text_to_speech"] = tts_setting
            
            # If we have vulnerabilities, update the filtered list
            if st.session_state.vulnerabilities:
                st.session_state.filtered_vulnerabilities = filter_vulnerabilities(
                    st.session_state.vulnerabilities, severity_filter)
                st.rerun()
        
        # About section
        st.subheader("About")
        st.markdown("""
        **PatchWise OS v2.0**
        
        An intelligent vulnerability assessment and mitigation platform powered by 
        RAG (Retrieval Augmented Generation) and AI analysis.
        
        © 2025 PatchWise Security
        """)

if __name__ == "__main__":
    main()
