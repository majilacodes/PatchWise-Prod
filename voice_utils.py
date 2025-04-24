import streamlit as st
import io
import tempfile
import gtts
from gtts import gTTS
import os
import base64
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Flag to track if speech recognition is available
SPEECH_RECOGNITION_AVAILABLE = False

# Flag to track if Google Cloud Speech API is available
GOOGLE_CLOUD_SPEECH_AVAILABLE = False

# Try to import speech recognition, but handle if it's not available
try:
    import speech_recognition as sr
    SPEECH_RECOGNITION_AVAILABLE = True
except ImportError:
    pass

# Try to import Google Cloud Speech
try:
    from google.cloud import speech
    GOOGLE_CLOUD_SPEECH_AVAILABLE = True
except ImportError:
    pass

# Try to import PyAudio to check if it's available
PYAUDIO_AVAILABLE = False
if SPEECH_RECOGNITION_AVAILABLE:
    try:
        with sr.Microphone() as source:
            PYAUDIO_AVAILABLE = True
    except (ImportError, AttributeError, OSError):
        PYAUDIO_AVAILABLE = False

def check_google_cloud_api_key():
    """Check if Google Cloud API credentials are properly configured"""
    api_key = os.getenv("GOOGLE_CLOUD_API_KEY")
    creds_file = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    
    if api_key or creds_file:
        return True
    return False

def check_voice_input_capability():
    """Check if the system can use voice input"""
    if GOOGLE_CLOUD_SPEECH_AVAILABLE and check_google_cloud_api_key():
        return True
    return SPEECH_RECOGNITION_AVAILABLE and PYAUDIO_AVAILABLE

def recognize_speech_with_google_cloud(audio_data, language='en-US'):
    """
    Recognize speech using Google Cloud Speech-to-Text API
    
    Args:
        audio_data: Audio data bytes
        language: Language code for recognition
    
    Returns:
        Recognized text or error message
    """
    if not GOOGLE_CLOUD_SPEECH_AVAILABLE:
        return "Google Cloud Speech API is not available. Please install google-cloud-speech package."
    
    if not check_google_cloud_api_key():
        return "Google Cloud API credentials not found. Please set GOOGLE_APPLICATION_CREDENTIALS environment variable."
    
    try:
        client = speech.SpeechClient()
        
        # Configure request
        config = speech.RecognitionConfig(
            encoding=speech.RecognitionConfig.AudioEncoding.LINEAR16,
            sample_rate_hertz=16000,
            language_code=language,
            enable_automatic_punctuation=True,
        )
        
        # Create audio content
        audio = speech.RecognitionAudio(content=audio_data)
        
        # Send request
        response = client.recognize(config=config, audio=audio)
        
        # Process response
        transcript = ""
        for result in response.results:
            transcript += result.alternatives[0].transcript
        
        if transcript:
            return transcript
        else:
            return "No speech detected"
            
    except Exception as e:
        return f"Error with Google Cloud Speech API: {str(e)}"

def recognize_speech(language='en'):
    """
    Recognize speech using the SpeechRecognition library or Google Cloud.
    
    Args:
        language: Language code for recognition
    
    Returns:
        Recognized text or error message
    """
    # Map language codes to recognition language
    language_codes = {
        'en': 'en-US',
        'es': 'es-ES',
        'fr': 'fr-FR',
        'de': 'de-DE',
        'zh': 'zh-CN',
        'ja': 'ja-JP',
        'ru': 'ru-RU',
        'ar': 'ar-SA'
    }
    
    lang_code = language_codes.get(language, 'en-US')
    
    # Check if Google Cloud Speech API should be used
    use_google_cloud = GOOGLE_CLOUD_SPEECH_AVAILABLE and check_google_cloud_api_key()
    
    if not SPEECH_RECOGNITION_AVAILABLE:
        return "Speech recognition is not available. Please install speech_recognition package."
    
    if not PYAUDIO_AVAILABLE:
        return "PyAudio is not installed. Voice input requires PyAudio. Please run 'pip install pyaudio' or upload audio instead."
    
    try:
        recognizer = sr.Recognizer()
        with sr.Microphone() as source:
            st.info("Listening... Please speak.")
            try:
                audio = recognizer.listen(source, timeout=5)
                
                if use_google_cloud:
                    # Convert audio data for Google Cloud API
                    audio_data = audio.get_wav_data()
                    return recognize_speech_with_google_cloud(audio_data, lang_code)
                else:
                    # Use the built-in Google recognizer
                    return recognizer.recognize_google(audio, language=lang_code)
                    
            except sr.UnknownValueError:
                return "Sorry, I could not understand your speech."
            except sr.RequestError as e:
                return f"Error with the speech recognition service: {e}"
    except Exception as e:
        return f"Error: {e}"

def generate_audio(text, language="en"):
    """
    Generate audio from text using gTTS.
    
    Args:
        text: Text to convert to speech
        language: Language code
    
    Returns:
        Audio bytes or None if failed
    """
    try:
        tts = gTTS(text=text, lang=language, slow=False)
        audio_buffer = io.BytesIO()
        tts.write_to_fp(audio_buffer)
        audio_buffer.seek(0)
        return audio_buffer.read()
    except Exception as e:
        st.error(f"Error generating audio: {str(e)}")
        return None

def display_voice_input_options(current_language="en"):
    """
    Display voice input options based on available functionality
    
    Args:
        current_language: Current language code
    
    Returns:
        User input text or None
    """
    user_input = None
    
    # Map language codes
    language_codes = {
        'en': 'en-US',
        'es': 'es-ES',
        'fr': 'fr-FR',
        'de': 'de-DE',
        'zh': 'zh-CN',
        'ja': 'ja-JP',
        'ru': 'ru-RU',
        'ar': 'ar-SA'
    }
    lang_code = language_codes.get(current_language, 'en-US')
    
    # Check if we can use Google Cloud API
    use_google_cloud = GOOGLE_CLOUD_SPEECH_AVAILABLE and check_google_cloud_api_key()
    
    if check_voice_input_capability():
        # Display which API will be used
        if use_google_cloud:
            st.info("Using Google Cloud Speech API for enhanced accuracy")
        
        # If PyAudio is available, show the speak button
        if st.button("🎤 Speak your question"):
            with st.spinner("Listening..."):
                speech_text = recognize_speech(current_language)
                if not speech_text.startswith("Error") and not speech_text.startswith("Sorry"):
                    user_input = speech_text
                else:
                    st.error(speech_text)
    else:
        # If voice input is not available, show installation instructions
        with st.expander("Voice Input Not Available"):
            st.warning("""
            Voice input requires PyAudio, which is not installed or accessible.
            
            To enable voice input:
            
            1. Install PyAudio using pip:
               ```
               pip install pyaudio
               ```
               
            2. On macOS, you might need to install portaudio first:
               ```
               brew install portaudio
               pip install pyaudio
               ```
               
            3. On Linux:
               ```
               sudo apt-get install python3-pyaudio
               ```
               
            For enhanced speech recognition accuracy, install Google Cloud Speech:
            ```
            pip install google-cloud-speech
            ```
            
            And set up your Google Cloud credentials in the .env file.
            
            You can still use text input below.
            """)
        
        # Provide file upload as alternative
        st.write("As an alternative, you can upload an audio file:")
        audio_file = st.file_uploader("Upload audio file (mp3, wav)", type=["mp3", "wav"])
        
        if audio_file is not None:
            # Save uploaded file temporarily
            with tempfile.NamedTemporaryFile(delete=False, suffix="."+audio_file.name.split(".")[-1]) as tmp_file:
                tmp_file.write(audio_file.getvalue())
                tmp_file_path = tmp_file.name
            
            try:
                # Process the audio file
                if use_google_cloud:
                    # Read the file content for Google Cloud API
                    with open(tmp_file_path, "rb") as audio_file:
                        audio_content = audio_file.read()
                    
                    # Use Google Cloud Speech API
                    text = recognize_speech_with_google_cloud(audio_content, lang_code)
                else:
                    # Use the built-in recognizer
                    recognizer = sr.Recognizer()
                    with sr.AudioFile(tmp_file_path) as source:
                        audio_data = recognizer.record(source)
                        text = recognizer.recognize_google(audio_data, language=lang_code)
                
                st.success(f"Recognized: {text}")
                user_input = text
            except Exception as e:
                st.error(f"Error processing audio: {str(e)}")
            finally:
                # Clean up the temporary file
                try:
                    os.unlink(tmp_file_path)
                except:
                    pass
    
    return user_input
