import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk
import wave
import threading
import time
import json
import cv2
import numpy as np
import pyaudio
import librosa
import os
import sys
import requests
import random
from datetime import datetime


def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

class SmartSecurityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Smart Security System (Real Sensors)")
        self.root.geometry("800x600")
        
        # Configuration
        self.SOUND_THRESHOLD = 0.03
        self.MOTION_THRESHOLD = 10000
        self.EVENT_COOLDOWN = 10
        self.RECORDING_DURATION = 10
        
        # API Configuration
        self.API_BASE_URL = "http://localhost:8000/"  # Django API URL
        self.MAX_IMAGES = 3
        self.MAX_AUDIO = 3
        self.EVIDENCE_INTERVAL = 5  # seconds
        self.last_api_send_time = 0
        self.sent_images = 0
        self.sent_audio = 0
        self.incident_id = None
        
        # State variables
        self.last_event_time = 0
        self.motion_detected = tk.IntVar(value=0)
        self.sound_detected = tk.IntVar(value=0)
        self.incidents = []
        self.detection_active = False
        self.is_recording = False
        self.frames = []
        self.recording_start_time = 0
        self.cap = None
        self.audio = None
        self.stream = None
        
        # Initialize resources
        self.initialize_camera()
        self.initialize_audio()
        self.initialize_evidence_dir()
        self.load_incidents()
        
        # GUI setup
        self.setup_ui()
        threading.Thread(target=self.poll_detection_flag, daemon=True).start()


    def resource_path(relative_path):
        """ Get absolute path to resource, works for dev and for PyInstaller """
        try:
            base_path = sys._MEIPASS
        except Exception:
            base_path = os.path.abspath(".")
        return os.path.join(base_path, relative_path)


    def initialize_camera(self):
        """Initialize camera with error handling"""
        try:
            self.cap = cv2.VideoCapture(0)
            if not self.cap.isOpened():
                raise RuntimeError("Could not initialize camera")
            # Test camera
            ret, _ = self.cap.read()
            if not ret:
                raise RuntimeError("Camera test frame failed")
        except Exception as e:
            messagebox.showerror("Camera Error", f"Camera initialization failed: {str(e)}")
            self.cap = None

    def initialize_audio(self):
        """Initialize audio with error handling"""
        try:
            self.audio = pyaudio.PyAudio()
            # Test audio devices
            if not self.audio.get_device_count():
                raise RuntimeError("No audio devices found")
        except Exception as e:
            messagebox.showwarning("Audio Warning", f"Audio initialization failed: {str(e)}")
            self.audio = None

    def initialize_evidence_dir(self):
        """Create evidence directory with error handling"""
        try:
            os.makedirs(resource_path("evidence"), exist_ok=True)
        except Exception as e:
            messagebox.showerror("Storage Error", f"Cannot create evidence directory: {str(e)}")

    def setup_ui(self):
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left panel - Camera feed
        left_frame = ttk.Frame(main_frame, width=500)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.video_label = tk.Label(left_frame, bg='green')
        self.video_label.pack(fill=tk.BOTH, expand=True)
        
        # Right panel - Controls
        right_frame = ttk.Frame(main_frame, width=300)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=10)
        
        # Detection control frame
        control_frame = ttk.LabelFrame(right_frame, text="Detection Control", padding=10)
        control_frame.pack(fill=tk.X, pady=5)
        
        self.start_button = ttk.Button(
            control_frame, 
            text="Start Detection", 
            command=self.start_detection,
            state=tk.NORMAL if self.cap else tk.DISABLED
        )
        self.start_button.pack(side=tk.LEFT, expand=True)
        
        self.stop_button = ttk.Button(
            control_frame, 
            text="Stop Detection", 
            command=self.stop_detection,
            state=tk.DISABLED
        )
        self.stop_button.pack(side=tk.RIGHT, expand=True)
        
        # Sensor Status Frame
        status_frame = ttk.LabelFrame(right_frame, text="Sensor Status", padding=10)
        status_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(status_frame, text="Motion:").grid(row=0, column=0, sticky=tk.W)
        ttk.Label(status_frame, textvariable=self.motion_detected).grid(row=0, column=1, sticky=tk.E)
        
        ttk.Label(status_frame, text="Sound:").grid(row=1, column=0, sticky=tk.W)
        sound_status = ttk.Label(status_frame, textvariable=self.sound_detected)
        sound_status.grid(row=1, column=1, sticky=tk.E)
        if not self.audio:
            sound_status.config(foreground='gray')
        
        # Incident Report Frame
        report_frame = ttk.LabelFrame(right_frame, text="Report Incident", padding=10)
        report_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(report_frame, text="Type:").grid(row=0, column=0, sticky=tk.W)
        self.incident_type = ttk.Combobox(report_frame, values=["Suspicious Activity", "Theft", "Vandalism"])
        self.incident_type.grid(row=0, column=1, sticky=tk.EW, pady=2)
        
        ttk.Label(report_frame, text="Description:").grid(row=1, column=0, sticky=tk.NW)
        self.incident_desc = tk.Text(report_frame, height=4, width=25)
        self.incident_desc.grid(row=1, column=1, sticky=tk.EW, pady=2)
        
        ttk.Button(report_frame, text="Submit Report", command=self.submit_report).grid(row=2, columnspan=2, pady=5)
        
        # Alerts Log
        alert_frame = ttk.LabelFrame(right_frame, text="Alerts", padding=10)
        alert_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.alert_log = tk.Text(alert_frame, height=10, state="disabled")
        self.alert_log.pack(fill=tk.BOTH, expand=True)

    def start_detection(self):
        """Start the motion and sound detection."""
        if not self.cap:
            messagebox.showerror("Error", "Camera not available")
            return

        self.detection_active = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.add_alert("🟢 Detection system activated")

        # Start sensor threads
        threading.Thread(target=self.motion_detection, daemon=True).start()
        if self.audio:
            threading.Thread(target=self.sound_detection, daemon=True).start()

        self.update_camera()


    def stop_detection(self):
        """Stop the motion and sound detection."""
        self.detection_active = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.add_alert("🔴 Detection system deactivated")


    def poll_detection_flag(self):
        """Poll Django API for remote detection start/stop commands."""
        while True:
            try:
                response = requests.get("http://127.0.0.1:8000/detection-status/")
                if response.status_code == 200:
                    status = response.json().get("status")
                    if status == "start" and not self.detection_active:
                        print("[REMOTE] Starting detection...")
                        self.start_detection()
                    elif status == "stop" and self.detection_active:
                        print("[REMOTE] Stopping detection...")
                        self.stop_detection()
            except Exception as e:
                print(f"[REMOTE] Polling error: {e}")
            time.sleep(5)


    def update_camera(self):
        if self.detection_active and self.cap and self.cap.isOpened():
            try:
                ret, frame = self.cap.read()
                if ret:
                    frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                    frame = cv2.resize(frame, (640, 480))
                    self.current_frame = frame
                    
                    img = Image.fromarray(frame)
                    imgtk = ImageTk.PhotoImage(image=img)
                    
                    self.video_label.imgtk = imgtk
                    self.video_label.configure(image=imgtk)
            except Exception as e:
                self.add_alert(f"⚠️ Camera error: {str(e)}")
                self.stop_detection()
            
            self.root.after(30, self.update_camera)

    def motion_detection(self):
        try:
            _, prev_frame = self.cap.read()
            prev_gray = cv2.cvtColor(prev_frame, cv2.COLOR_BGR2GRAY)

            while self.detection_active and self.cap and self.cap.isOpened():
                ret, frame = self.cap.read()
                if not ret:
                    break

                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                diff = cv2.absdiff(prev_gray, gray)
                _, threshold = cv2.threshold(diff, 30, 255, cv2.THRESH_BINARY)
                motion = np.sum(threshold) > self.MOTION_THRESHOLD
                self.motion_detected.set(int(motion))
                
                prev_gray = gray
                time.sleep(0.1)
        except Exception as e:
            self.add_alert(f"⚠️ Motion detection error: {str(e)}")

    def sound_detection(self):
        try:
            self.stream = self.audio.open(
                format=pyaudio.paFloat32,
                channels=1,
                rate=44100,
                input=True,
                frames_per_buffer=1024,
                stream_callback=self.audio_callback
            )
            self.stream.start_stream()
            
            while self.detection_active and self.stream.is_active():
                time.sleep(0.1)
                
        except Exception as e:
            self.add_alert(f"⚠️ Sound detection error: {str(e)}")
        finally:
            if hasattr(self, 'stream') and self.stream:
                self.stream.stop_stream()
                self.stream.close()

    def audio_callback(self, in_data, frame_count, time_info, status):
        try:
            data = np.frombuffer(in_data, dtype=np.float32)
            rms = librosa.feature.rms(y=data)[0][0]
            sound = rms > self.SOUND_THRESHOLD
            self.sound_detected.set(int(sound))
            
            if sound and self.cooldown_expired():
                self.auto_report("Loud Noise", f"Sound level exceeded threshold ({rms:.2f})")
                # The mapping inside auto_report will convert it to SOUND
                self.last_event_time = time.time()
                self.start_recording()
                
            if self.is_recording:
                self.frames.append(in_data)
                if time.time() - self.recording_start_time >= self.RECORDING_DURATION:
                    self.save_audio_evidence()
                    self.is_recording = False
        except Exception as e:
            self.add_alert(f"⚠️ Audio processing error: {str(e)}")
        
        return (None, pyaudio.paContinue)

    def start_recording(self):
        if not self.is_recording:
            self.is_recording = True
            self.recording_start_time = time.time()
            self.frames = []
            self.add_alert("🔴 Recording started for 10 seconds")
            threading.Thread(target=self.record_video, daemon=True).start()

    def record_video(self):
        """Capture video frames during recording"""
        try:
            while self.is_recording and self.detection_active:
                if int(time.time() - self.recording_start_time) % 1 == 0:
                    self.capture_evidence("motion")
                time.sleep(0.5)
        except Exception as e:
            self.add_alert(f"⚠️ Video recording error: {str(e)}")

    def save_audio_evidence(self):
        """Save recorded audio to WAV file."""
        try:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = resource_path(f"evidence/sound_{timestamp}.wav")
            
            with wave.open(filename, 'wb') as wf:
                wf.setnchannels(1)
                wf.setsampwidth(self.audio.get_sample_size(pyaudio.paFloat32))
                wf.setframerate(44100)
                wf.writeframes(b''.join(self.frames))
            
            self.add_alert(f"🔊 Audio evidence saved: {filename}")
        except Exception as e:
            self.add_alert(f"⚠️ Failed to save audio: {str(e)}")

    def capture_evidence(self, prefix):
        if self.current_frame is not None:
            try:
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                filename = resource_path(f"evidence/{prefix}_{timestamp}.jpg")
                cv2.imwrite(filename, cv2.cvtColor(self.current_frame, cv2.COLOR_RGB2BGR))
                self.add_alert(f"📸 Evidence saved: {filename}")
            except Exception as e:
                self.add_alert(f"⚠️ Failed to save image: {str(e)}")

    def cooldown_expired(self):
        return time.time() - self.last_event_time > self.EVENT_COOLDOWN

    def send_to_api(self, endpoint, data, files=None):
        """Helper method to send data to API"""
        try:
            url = f"{self.API_BASE_URL}/{endpoint}/"
            if files:
                response = requests.post(url, data=data, files=files)
            else:
                response = requests.post(url, json=data)
                
            if response.status_code == 201:
                self.add_alert(f"✅ Successfully sent to {endpoint}")
                return response.json()
            else:
                self.add_alert(f"⚠️ API Error ({response.status_code}): {response.text}")
        except requests.exceptions.RequestException as e:
            self.add_alert(f"⚠️ API Connection Failed: {str(e)}")
        except Exception as e:
            self.add_alert(f"⚠️ API Error: {str(e)}")
        return None


    def save_audio_evidence(self):
        """Save recorded audio to WAV file and send to API with limits"""
        try:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = resource_path(f"evidence/sound_{timestamp}.wav")
            
            with wave.open(filename, 'wb') as wf:
                wf.setnchannels(1)
                wf.setsampwidth(self.audio.get_sample_size(pyaudio.paFloat32))
                wf.setframerate(44100)
                wf.writeframes(b''.join(self.frames))
            
            self.add_alert(f"🔊 Audio evidence saved: {filename}")
            
            # Send to API if we haven't reached the limit and have an incident
            current_time = time.time()
            if (self.incident_id and 
                self.sent_audio < self.MAX_AUDIO and 
                current_time - self.last_api_send_time >= self.EVIDENCE_INTERVAL):
                
                try:
                    with open(filename, 'rb') as audio_file:
                        evidence_data = {
                            "incident": self.incident_id,
                            "evidence_type": "AUDIO",
                            "timestamp": datetime.now().isoformat()
                        }
                        files = {'file': (os.path.basename(filename), audio_file, 'audio/wav')}
                        self.send_to_api("evidences", evidence_data, files=files)
                        self.sent_audio += 1
                        self.last_api_send_time = current_time
                except Exception as e:
                    self.add_alert(f"⚠️ Failed to send audio to API: {str(e)}")
                    
        except Exception as e:
            self.add_alert(f"⚠️ Failed to save audio: {str(e)}")

    def capture_evidence(self, prefix):
        """Capture image evidence and send to API with limits"""
        if self.current_frame is not None:
            try:
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                filename = resource_path(f"evidence/{prefix}_{timestamp}.jpg")
                cv2.imwrite(filename, cv2.cvtColor(self.current_frame, cv2.COLOR_RGB2BGR))
                self.add_alert(f"📸 Evidence saved: {filename}")
                
                # Send to API if we haven't reached the limit and have an incident
                current_time = time.time()
                if (self.incident_id and 
                    self.sent_images < self.MAX_IMAGES and 
                    current_time - self.last_api_send_time >= self.EVIDENCE_INTERVAL):
                    
                    try:
                        with open(filename, 'rb') as image_file:
                            evidence_data = {
                                "incident": self.incident_id,
                                "evidence_type": "IMAGE",
                                "timestamp": datetime.now().isoformat()
                            }
                            files = {'file': (os.path.basename(filename), image_file, 'image/jpeg')}
                            self.send_to_api("evidences", evidence_data, files=files)
                            self.sent_images += 1
                            self.last_api_send_time = current_time
                    except Exception as e:
                        self.add_alert(f"⚠️ Failed to send image to API: {str(e)}")
                        
            except Exception as e:
                self.add_alert(f"⚠️ Failed to save image: {str(e)}")

    def cooldown_expired(self):
        return time.time() - self.last_event_time > self.EVENT_COOLDOWN

    def auto_report(self, event_type, description):
        """Handle automatic incident reporting with API integration"""
        incident_data = {
            "device_id": "Hor92311A",
            "incident_type": event_type,
            "description": description,
            "severity": random.randint(1, 3),
            "is_verified": False,
            "timestamp": datetime.now().isoformat(),
            "alert_message": "System-generated alert",
            "device_location": "Main Gate",
            "neighborhood": "Zone A",
            "evidence_type": "IMAGE",
            "ai_analysis": None
        }

        # Submit the incident
        api_response = self.send_to_api("incidents", incident_data)
        if api_response:
            self.incident_id = api_response.get('id')
            self.upload_evidence_files(self.incident_id)
        else:
            self.incident_id = None

        # Save locally
        incident = {
            "type": event_type,
            "desc": description,
            "time": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        self.incidents.append(incident)
        self.save_incidents()
        self.add_alert(f"⚠️ AUTO-REPORT: {event_type}")
        self.video_label.config(bg="red")
        self.root.after(1000, lambda: self.video_label.config(bg="black"))
        self.sent_images = 0
        self.sent_audio = 0
        self.last_api_send_time = time.time()

    def submit_report(self):
        """Handle manual incident report submission with API integration"""
        incident_type = self.incident_type.get()
        description = self.incident_desc.get("1.0", tk.END).strip()

        if not incident_type or not description:
            messagebox.showerror("Error", "Please fill in all fields")
            return

        incident_data = {
            "device_id": "Hor92311A",
            "incident_type": incident_type.upper(),
            "description": description,
            "severity": random.randint(2, 5),
            "is_verified": False,
            "timestamp": datetime.now().isoformat(),

            # New fields
            "alert_message": "Manual alert",
            "device_location": "Main Gate",
            "neighborhood": "Zone A",
            "evidence_type": "IMAGE",
            "ai_analysis": None
        }

        api_response = self.send_to_api("incidents", incident_data)
        if api_response:
            self.incident_id = api_response.get('id')
        else:
            self.incident_id = None

        incident = {
            "type": incident_type,
            "desc": description,
            "time": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        self.incidents.append(incident)
        self.save_incidents()
        self.add_alert(f"📢 MANUAL REPORT: {incident_type}")
        self.incident_desc.delete("1.0", tk.END)
        messagebox.showinfo("Success", "Incident reported successfully!")

        self.sent_images = 0
        self.sent_audio = 0
        self.last_api_send_time = time.time()
    
    def upload_evidence_files(self, incident_id):
        """Upload 3 random images from local folder and attach them to the incident"""
        evidence_dir = "evidence/images/"
        if not os.path.exists(evidence_dir):
            print("Evidence folder not found")
            return

        images = [f for f in os.listdir(evidence_dir) if f.lower().endswith((".png", ".jpg", ".jpeg"))]
        if not images:
            print("No images found in evidence folder")
            return

        selected_images = random.sample(images, min(3, len(images)))

        for img_name in selected_images:
            img_path = os.path.join(evidence_dir, img_name)
            files = {
                'evidence_file': open(img_path, 'rb')
            }
            data = {
                'incident': incident_id,
                'evidence_type': 'IMAGE'
            }
            try:
                response = requests.post(f"{self.api_base}/evidences/", files=files, data=data)
                if response.status_code in [200, 201]:
                    print(f"Uploaded: {img_name}")
                else:
                    print(f"Failed to upload {img_name}: {response.status_code} - {response.text}")
            except Exception as e:
                print(f"Error uploading {img_name}: {e}")

    

    def load_incidents(self):
        """Load incidents from JSON file."""
        try:
            with open(resource_path("incidents.json"), "r") as f:
                self.incidents = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.incidents = []

    def save_incidents(self):
        """Save incidents to JSON file."""
        try:
            with open(resource_path("incidents.json"), "w") as f:
                json.dump(self.incidents, f)
        except Exception as e:
            self.add_alert(f"⚠️ Failed to save incidents: {str(e)}")

    def add_alert(self, message):
        """Display alerts in the GUI."""
        self.alert_log.config(state="normal")
        self.alert_log.insert("end", f"[{time.strftime('%H:%M:%S')}] {message}\n")
        self.alert_log.config(state="disabled")
        self.alert_log.see("end")

    def on_close(self):
        """Clean up resources when closing the window."""
        self.detection_active = False
        time.sleep(0.5)  # Give threads time to stop
        
        try:
            if hasattr(self, 'cap') and self.cap and self.cap.isOpened():
                self.cap.release()
        except:
            pass
        
        try:
            if hasattr(self, 'stream') and self.stream:
                self.stream.stop_stream()
                self.stream.close()
        except:
            pass
        
        try:
            if hasattr(self, 'audio') and self.audio:
                self.audio.terminate()
        except:
            pass
        
        cv2.destroyAllWindows()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = SmartSecurityApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()