import asyncio
import random
import subprocess
import customtkinter as ctk
import queue
import threading
import os
import shutil
import uuid
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta, timezone
import ssl


log_queue = queue.Queue()
class AsyncProxyServer:
    def __init__(self, host="127.0.0.1", port=None):
        self.host = host
        self.port = port or random.randrange(9000, 10000)
        self.proxy = f"{self.host}:{self.port}"

        self.log_queue = log_queue

        self.cert_dir = "certs" #certificates
        self.ca_cert = os.path.join(self.cert_dir, "my_proxy_ca.crt")
        self.ca_key = os.path.join(self.cert_dir, "my_proxy_ca.key")
        self.cert_dir = os.path.join(self.cert_dir, "cache") #cache
        os.makedirs(self.cert_dir, exist_ok=True) # Ensures parent and child dirs exist

        self.filter_rules = {
            "protocol": "All",  # "All", "HTTP", or "HTTPS"
            "port": "",         # e.g., "443"
            "include_host": "", # e.g., "example.com"
            "exclude_host": ""  # e.g., "telemetry.microsoft.com"
        }
        

    async def start(self):
        server = await asyncio.start_server(
            self.handle_client, self.host, self.port
        )

        print(f"[~] Async proxy running on {self.proxy}")


        async with server:
            await server.serve_forever()


    async def handle_client(self, reader, writer):
        try:
            data = await reader.read(65536)
            if not data:
                writer.close()
                await writer.wait_closed()
                return

            first_line = data.split(b"\r\n")[0]
            if first_line.startswith(b"CONNECT"):
                await self.handle_connect(first_line, reader, writer)
            else:
                await self.handle_http(data, reader, writer)

        except Exception as e:
            print("[ERROR]", e)
        
        finally:
            #cleanup for the main client writer
            if not writer.is_closing():
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass


    def forward_request(self, req_id, modified_data=None):
        """Thread-safe method called by the GUI to release a paused request, optionally with new data."""
        if hasattr(self, 'pending_requests') and req_id in self.pending_requests:
            # If the GUI sent us modified text, save it
            if modified_data is not None:
                if not hasattr(self, 'modified_payloads'):
                    self.modified_payloads = {}
                self.modified_payloads[req_id] = modified_data

            event = self.pending_requests[req_id]
            if hasattr(self, 'loop'):
                self.loop.call_soon_threadsafe(event.set)


    async def handle_http(self, data, client_reader, client_writer, https=False):
        is_intercepted_this_request = False
        try:
            # Initialize state variables
            if not hasattr(self, 'pending_requests'):
                self.pending_requests = {}
            if not hasattr(self, 'intercept_on'):
                self.intercept_on = False
            if not hasattr(self, 'loop'):
                self.loop = asyncio.get_running_loop()

            req_id = str(uuid.uuid4())
            intercept_event = asyncio.Event()
            self.pending_requests[req_id] = intercept_event

            headers = data.decode(errors="ignore").split("\r\n")
            host_line = [h for h in headers if h.lower().startswith("host:")][0]

            host_raw = host_line.split(":", 1)[1].strip()
            if ":" in host_raw:
                host, port = host_raw.split(":")
                port = int(port)
            else:
                host = host_raw
                port = 443 if https else 80

            first_line = headers[0] if headers else "UNKNOWN REQUEST"
            method = first_line.split()[0] if len(first_line.split()) > 0 else ""

            if self.intercept_on:
                is_intercepted_this_request = True
                should_intercept = True

                #Protocol Filter
                if self.filter_rules["protocol"] == "HTTP" and https:
                    should_intercept = False
                elif self.filter_rules["protocol"] == "HTTPS" and not https:
                    should_intercept = False
                    
                #Port Filter
                if self.filter_rules["port"] and str(port) != self.filter_rules["port"]:
                    should_intercept = False
                    
                #Blacklist
                if self.filter_rules["exclude_host"]:
                    # Split by comma, clean up spaces, and check if any match
                    excluded_hosts = [h.strip().lower() for h in self.filter_rules["exclude_host"].split(",") if h.strip()]
                    if any(ex_host in host.lower() for ex_host in excluded_hosts):
                        should_intercept = False
                    
                #Whitelist
                if self.filter_rules["include_host"]:
                    included_hosts = [h.strip().lower() for h in self.filter_rules["include_host"].split(",") if h.strip()]
                    # If none of the whitelisted hosts are in the current host, do not intercept
                    if not any(inc_host in host.lower() for inc_host in included_hosts):
                        should_intercept = False
                    
                is_intercepted_this_request = should_intercept

            status_tag = "[PAUSED] " if is_intercepted_this_request else ""
            summary = f"{status_tag}{method} {host}:{port}"
            raw_request = data.decode(errors="ignore")

            self.log_queue.put({
                "req_id": req_id,
                "summary": summary,
                "details": raw_request,
                "is_paused": is_intercepted_this_request
            })

            if is_intercepted_this_request:
                print(f"[~] Intercepted and holding request to {host}...")
                await intercept_event.wait() 
            
            # Swap the payload if the user edited i
            payload_to_send = data # Default to original data
            
            if hasattr(self, 'modified_payloads') and req_id in self.modified_payloads:
                modified_text = self.modified_payloads.pop(req_id)
                modified_text = modified_text.replace('\r\n', '\n').replace('\n', '\r\n')
                payload_to_send = modified_text.encode(errors="ignore")

            self.pending_requests.pop(req_id, None)


            client_ssl_ctx = None
            if https: #setup for tls handshake with the websie
                client_ssl_ctx = ssl.create_default_context()
                client_ssl_ctx.check_hostname = False
                client_ssl_ctx.verify_mode = ssl.CERT_NONE

            # Open connection to the real remote server
            remote_reader, remote_writer = await asyncio.open_connection(
                host, port, ssl=client_ssl_ctx #if none then http
            )
            
            # Send the final payload (either original or edited)
            remote_writer.write(payload_to_send)
            await remote_writer.drain()

            await asyncio.gather(
                self.pipe(client_reader, remote_writer),
                self.pipe(remote_reader, client_writer)
            )

        except Exception as e:
            print("[HTTP ERROR]", e)
            self.pending_requests.pop(req_id, None)


    async def handle_connect(self, first_line, client_reader, client_writer):
        secure_writer = None
        hostname = "UNKNOWN"
        try:
            target = first_line.split()[1]
            host_bytes, port_bytes = target.split(b":")
            hostname = host_bytes.decode()
            port = int(port_bytes.decode())

            #check filters
            should_pass_through = False
            
            # Check blacklist
            if self.filter_rules["exclude_host"]:
                excluded_hosts = [h.strip().lower() for h in self.filter_rules["exclude_host"].split(",") if h.strip()]
                if any(ex_host in hostname.lower() for ex_host in excluded_hosts):
                    should_pass_through = True
                    
            # Check whitelist
            elif self.filter_rules["include_host"]:
                included_hosts = [h.strip().lower() for h in self.filter_rules["include_host"].split(",") if h.strip()]
                if not any(inc_host in hostname.lower() for inc_host in included_hosts):
                    should_pass_through = True

            # IF PASS-THROUGH, DO A DIRECT CONNECTION (NO FAKE CERTS)
            if should_pass_through:
                try:
                    remote_reader, remote_writer = await asyncio.open_connection(hostname, port)
                    
                    # Tell browser the tunnel is ready
                    client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    await client_writer.drain()
                    
                   
                    await asyncio.gather(
                        self.pipe(client_reader, remote_writer),
                        self.pipe(remote_reader, client_writer)
                    )
                    return  # Now it safely returns only when the connection naturally ends
                except Exception as e:
                    print(f"[~] Pass-through connection failed for {hostname}: {e}")
                    return

            #IF WE ARE INTERCEPTING, DO THE MITM TLS HANDSHAKE
            client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await client_writer.drain()

            cert_path, key_path = self.generate_cert(hostname)

            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(certfile=cert_path, keyfile=key_path)

            loop = asyncio.get_running_loop()

            new_reader = asyncio.StreamReader()
            new_protocol = asyncio.StreamReaderProtocol(new_reader)
            
            transport = client_writer.transport
            secure_transport = await loop.start_tls(
                transport, 
                new_protocol, 
                ssl_context, 
                server_side=True
            )

            secure_writer = asyncio.StreamWriter(secure_transport, new_protocol, new_reader, loop)

            while True:
                data = await new_reader.read(65536)
                if not data:
                    break
                await self.handle_http(data, new_reader, secure_writer, https=True)

        except Exception as e:
            pass # Keep console clean
            
        finally:
            # Bulletproof cleanup
            if secure_writer is not None and not secure_writer.is_closing():
                try:
                    secure_writer.close()
                    await secure_writer.wait_closed()
                except Exception:
                    pass

                

    async def pipe(self, reader, writer):
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except:
            pass
        finally:
            writer.close()


    #https mitm helper functions
    def generate_cert(self, hostname):
        #forgeing certificate if needed to an hostname

        cert_path = os.path.join(self.cert_dir, f"{hostname}.crt")
        key_path = os.path.join(self.cert_dir, f"{hostname}.key")

        if os.path.exists(cert_path) and os.path.exists(key_path):
            return cert_path, key_path
        
        print(f"[~] Generating certificate for {hostname}")

        forged_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        with open(self.ca_cert, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        

        with open(self.ca_key, "rb") as f:
            ca_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )
        
        #who the site is
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])

        now = datetime.now(timezone.utc)
        cert_start = now - timedelta(days=1) #avoid clock delay errors
        cert_end = now + timedelta(days=365)

        forged_cert = (
            x509.CertificateBuilder().subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(forged_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(cert_start)
            .not_valid_after(cert_end)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False,)
            .sign(ca_key, hashes.SHA256()) #sign it 
        )

        #save to cache:
        with open(cert_path, "wb") as f:
            f.write(forged_cert.public_bytes(serialization.Encoding.PEM))
        
        with open(key_path, "wb") as f:
            f.write(forged_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        return cert_path, key_path


class ProxyGUI(ctk.CTk):
    def __init__(self, proxy):
        super().__init__()

        self.proxy = proxy
        self.browser_process = None 
        self.profile_path = r"C:\temp\edge-proxy-profile" 
        self.selected_req_id = None 
        self.history_buttons = {} 
        self.keep_logs = True 
        
        self.title("Proxy Tool")
        self.geometry("900x700") 
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        #controls frame
        self.controls_frame = ctk.CTkFrame(self)
        self.controls_frame.pack(fill="x", padx=10, pady=10)

        self.open_btn = ctk.CTkButton(self.controls_frame, text="Open Browser", width=1, command=self.open_browser)
        self.open_btn.pack(side="left", expand=True, fill="x", padx=5)

        self.intercept_btn = ctk.CTkButton(
            self.controls_frame, text="Intercept is OFF", fg_color="gray", width=1, command=self.toggle_intercept
        )
        self.intercept_btn.pack(side="left", expand=True, fill="x", padx=5)

        self.filter_btn = ctk.CTkButton(
            self.controls_frame, text="Filters ⚙️", fg_color="#404040", hover_color="#2b2b2b", width=1, command=self.open_filter_window
        )
        self.filter_btn.pack(side="left", expand=True, fill="x", padx=5)

        self.forward_btn = ctk.CTkButton(
            self.controls_frame, text="Forward", state="disabled", width=1, command=self.forward_selected
        )
        self.forward_btn.pack(side="left", expand=True, fill="x", padx=5)

        self.forward_all_btn = ctk.CTkButton(
            self.controls_frame, text="Forward All", fg_color="#c98a28", hover_color="#a8721e", width=1, command=self.forward_all_pending
        )
        self.forward_all_btn.pack(side="left", expand=True, fill="x", padx=5)

        self.keep_logs_btn = ctk.CTkButton(
            self.controls_frame, text="Keep Logs: ON", fg_color="#2c7a2c", hover_color="#1e5c1e", width=1, command=self.toggle_keep_logs
        )
        self.keep_logs_btn.pack(side="left", expand=True, fill="x", padx=5)


        #ui style
        self.history_frame = ctk.CTkScrollableFrame(self, height=200, label_text="HTTP History")
        self.history_frame.pack(fill="x", padx=10, pady=(0, 10))

        self.details_box = ctk.CTkTextbox(self, height=250)
        self.details_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.details_box.insert("end", "Select a request from the history to view details...")
        self.details_box.configure(state="disabled") 

        self.log_queue = log_queue
        self.poll_logs()

        self.paused_queue = [] 
        self.active_paused_req = None


    def open_filter_window(self):
        # Create a popup window
        filter_win = ctk.CTkToplevel(self)
        filter_win.title("Interception Filters")
        filter_win.geometry("400x400")
        filter_win.grab_set()  # Forces focus on this popup
        
        #Protocol filter
        ctk.CTkLabel(filter_win, text="Protocol:").pack(pady=(10, 0))
        protocol_var = ctk.StringVar(value=self.proxy.filter_rules["protocol"])
        protocol_menu = ctk.CTkOptionMenu(filter_win, values=["All", "HTTP", "HTTPS"], variable=protocol_var)
        protocol_menu.pack(pady=5)
        
        #Port filter
        ctk.CTkLabel(filter_win, text="Port (leave blank for any):").pack(pady=(10, 0))
        port_entry = ctk.CTkEntry(filter_win, placeholder_text="e.g., 443")
        port_entry.insert(0, self.proxy.filter_rules["port"])
        port_entry.pack(pady=5)
        
        #whitelist filter
        ctk.CTkLabel(filter_win, text="Only Intercept Hosts containing (comma-separated):").pack(pady=(10, 0))
        include_entry = ctk.CTkEntry(filter_win, placeholder_text="e.g., api.com, mytarget.org")
        include_entry.insert(0, self.proxy.filter_rules["include_host"])
        include_entry.pack(pady=5)
        
        #blacklist filter
        ctk.CTkLabel(filter_win, text="DO NOT Intercept Hosts containing (comma-separated):").pack(pady=(10, 0))
        exclude_entry = ctk.CTkEntry(filter_win, placeholder_text="e.g., microsoft.com, fonts.net")
        exclude_entry.insert(0, self.proxy.filter_rules["exclude_host"])
        exclude_entry.pack(pady=5)
        
        #Button Frame
        btn_frame = ctk.CTkFrame(filter_win, fg_color="transparent")
        btn_frame.pack(pady=20, fill="x", padx=20)
        
        def save_filters():
            self.proxy.filter_rules["protocol"] = protocol_var.get()
            self.proxy.filter_rules["port"] = port_entry.get().strip()
            self.proxy.filter_rules["include_host"] = include_entry.get().strip()
            self.proxy.filter_rules["exclude_host"] = exclude_entry.get().strip()
            
            # Visual feedback on the main button if filters are active
            active_filters = any([
                self.proxy.filter_rules["protocol"] != "All",
                self.proxy.filter_rules["port"],
                self.proxy.filter_rules["include_host"],
                self.proxy.filter_rules["exclude_host"]
            ])
            
            if active_filters:
                self.filter_btn.configure(fg_color="#0059b3", text="Filters (Active) ⚙️")
            else:
                self.filter_btn.configure(fg_color="#404040", text="Filters ⚙️")
            
            filter_win.destroy() # Close the popup


        def clear_filters():
            # Reset dictionary to defaults
            self.proxy.filter_rules = {
                "protocol": "All",
                "port": "",
                "include_host": "",
                "exclude_host": ""
            }
            # Reset button visual
            self.filter_btn.configure(fg_color="#404040", text="Filters ⚙️")
            filter_win.destroy() # Close the popup
            
        # Add the buttons side by side
        ctk.CTkButton(
            btn_frame, text="Clear Filters", fg_color="#8b2c2c", hover_color="#5c1d1d", width=1, command=clear_filters
        ).pack(side="left", expand=True, fill="x", padx=5)
        
        ctk.CTkButton(
            btn_frame, text="Save Filters", width=1, command=save_filters
        ).pack(side="left", expand=True, fill="x", padx=5)


    def open_browser(self):
        # Prevent opening multiple browser instances at once to avoid locking issues
        if self.browser_process and self.browser_process.poll() is None:
            self.log("[!] Browser is already running.")
            return

        self.browser_process = subprocess.Popen([
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            f"--proxy-server={self.proxy.proxy}",
            f"--user-data-dir={self.profile_path}",
            "--no-first-run",
            "--no-default-browser-check",
            "--new-window",
            "--disable-quic",
        ])

        self.log(f"[*] Browser launched. Profile: {self.profile_path}")

        # Start a background thread to wait for the user to close the browser normally
        cleanup_thread = threading.Thread(
            target=self.wait_and_cleanup, 
            args=(self.browser_process,), 
            daemon=True
        )
        cleanup_thread.start()


    def wait_and_cleanup(self, process):
        # This blocks only this background thread until the browser closes
        process.wait()
        self.log("[*] Browser closed by user. Cleaning up profile...")
        self.delete_profile()


    def delete_profile(self):
        # A helper method to safely delete the folder
        try:
            if os.path.exists(self.profile_path):
                shutil.rmtree(self.profile_path, ignore_errors=True)
                self.log(f"[*] Deleted {self.profile_path}")
        except Exception as e:
            self.log(f"[ERROR] Failed to delete profile: {e}")


    def on_closing(self):
        #This runs when the user clicks the X on the Tkinter GUI
        print("[~] Shutting down Proxy Tool...")
        
        #Kill the browser if it's still running
        if self.browser_process and self.browser_process.poll() is None:
            print("[~] Terminating browser process...")
            self.browser_process.terminate()
            self.browser_process.wait() # Wait for it to fully close

        #Clean up the profile folder
        self.delete_profile()

        #Destroy the GUI, which ends the main thread
        self.destroy()

    def show_details(self, details_text, req_id, is_paused):
        #more details about the packet
        self.selected_req_id = req_id
        
        self.details_box.configure(state="normal")   
        self.details_box.delete("1.0", "end")        
        self.details_box.insert("end", details_text) 

        # If it's paused: editable, else: disabled.
        if is_paused:
            self.forward_btn.configure(state="normal")
        else:
            self.forward_btn.configure(state="disabled")
            self.details_box.configure(state="disabled")


    def show_next_paused(self):
        #Pulls the next paused request from the hidden queue and displays it
        # If looking at a paused request, do nothing
        if self.active_paused_req is not None:
            return 
        
        # If the queue is empty, show a waiting message
        if not self.paused_queue:
            self.details_box.configure(state="normal")   
            self.details_box.delete("1.0", "end")        
            self.details_box.insert("end", "Waiting for intercepted requests...") 
            self.details_box.configure(state="disabled")
            self.forward_btn.configure(state="disabled")
            return

        # Get the next request in line
        msg = self.paused_queue.pop(0)
        self.active_paused_req = msg["req_id"]
        
        # Draw the button in the history list
        btn = ctk.CTkButton(
            self.history_frame, 
            text=msg["summary"], 
            anchor="w", 
            fg_color="transparent",
            hover_color=("gray70", "gray30"),
            text_color="orange",
            command=lambda d=msg["details"], r=msg["req_id"], p=True: self.show_details(d, r, p) 
        )
        btn.pack(fill="x", pady=1)
        self.history_buttons[msg["req_id"]] = btn
        
        # Auto-load it into the text box so you don't even have to click it!
        self.show_details(msg["details"], msg["req_id"], is_paused=True)


    def log(self, message):
        #Handles system messages and HTTP requests
        if isinstance(message, str):
            btn = ctk.CTkButton(
                self.history_frame, text=message, anchor="w", fg_color="transparent",
                hover_color=("gray70", "gray30"), text_color=("gray40", "gray60") 
            )
            btn.pack(fill="x", pady=1)
        
        elif isinstance(message, dict):
            req_id = message["req_id"]
            summary = message["summary"]
            details = message["details"]
            is_paused = message.get("is_paused", False)

            if is_paused:
                self.paused_queue.append(message)
                self.show_next_paused()
                return

            #if intercept and keep_logs is off, then don't show anything
            if not is_paused and not self.keep_logs:
                return

            #Make paused requests stand out in orange
            txt_color = "orange" if is_paused else ("black", "white")

            btn = ctk.CTkButton(
                self.history_frame, 
                text=summary, 
                anchor="w", 
                fg_color="transparent",
                hover_color=("gray70", "gray30"),
                text_color=txt_color,
                command=lambda d=details, r=req_id, p=is_paused: self.show_details(d, r, p) 
            )
            btn.pack(fill="x", pady=1)
            
            # Save the button in our dictionary so we can update/delete it later
            self.history_buttons[req_id] = btn


    def poll_logs(self):
        #Continuously pulls items from the queue and sends them to the log UI
        while not self.log_queue.empty():
            msg = self.log_queue.get()
            self.log(msg) 
        self.after(100, self.poll_logs)
    

    def forward_selected(self):
        #Forwards the currently selected request, sending any edits made in the textbox.
        if self.selected_req_id:
            
            #Grab the text from the editor ("end-1c" removes the hidden Tkinter newline)
            modified_text = self.details_box.get("1.0", "end-1c") #if we changed the packet contents
            
            if self.selected_req_id in self.history_buttons:
                btn = self.history_buttons[self.selected_req_id]
                
                if self.keep_logs:
                    new_text = btn.cget("text").replace("[PAUSED]", "[FORWARDED]")
                    btn.configure(text=new_text, text_color=("green", "lightgreen"))
                else:
                    btn.destroy()
                    del self.history_buttons[self.selected_req_id]
                    
                    self.details_box.configure(state="normal")   
                    self.details_box.delete("1.0", "end")        
                    self.details_box.insert("end", "Select a request from the history to view details...") 

            # Send the customized text to the proxy
            self.proxy.forward_request(self.selected_req_id, modified_text)
            
            self.forward_btn.configure(state="disabled")
            self.details_box.configure(state="disabled") # Lock the editor now that it's sent
            self.selected_req_id = None

            self.active_paused_req = None
            self.show_next_paused()


    def forward_all_pending(self):
        #send all intercepted requests
        if hasattr(self.proxy, 'pending_requests'):
            for req_id in list(self.proxy.pending_requests.keys()):
                
                modified_text = None
                #if the user is currently editing ONE of the paused requests in the window, 
                #we grab it before forwarding everything
                if req_id == self.selected_req_id:
                    modified_text = self.details_box.get("1.0", "end-1c")
                
                self.proxy.forward_request(req_id, modified_text)
                
                if req_id in self.history_buttons:
                    btn = self.history_buttons[req_id]
                    if self.keep_logs:
                        new_text = btn.cget("text").replace("[PAUSED]", "[FORWARDED]")
                        btn.configure(text=new_text, text_color=("green", "lightgreen"))
                    else:
                        btn.destroy()
                        del self.history_buttons[req_id]
            
            self.paused_queue.clear() 
            self.active_paused_req = None

            if not self.keep_logs:
                self.details_box.configure(state="normal")   
                self.details_box.delete("1.0", "end")        
                self.details_box.insert("end", "Select a request from the history to view details...") 
                        
        self.forward_btn.configure(state="disabled")
        self.details_box.configure(state="disabled") 
        self.selected_req_id = None



    def toggle_intercept(self):
        #Turns interception on or off and safely flushes paused requests
        if not hasattr(self.proxy, 'intercept_on'):
            self.proxy.intercept_on = False
            
        self.proxy.intercept_on = not self.proxy.intercept_on
        
        if self.proxy.intercept_on:
            self.intercept_btn.configure(text="Intercept is ON", fg_color="#ab2c2c") 
        else:
            self.intercept_btn.configure(text="Intercept is OFF", fg_color="gray")
            # Auto-forward any requests that are currently stuck waiting
            self.forward_all_pending()


    def toggle_keep_logs(self):
        #Toggles whether forwarded requests remain in the UI. Clears logs immediately if turned OFF
        self.keep_logs = not self.keep_logs
        
        if self.keep_logs:
            self.keep_logs_btn.configure(text="Keep Logs: ON", fg_color="#2c7a2c", hover_color="#1e5c1e") # Green
        else:
            self.keep_logs_btn.configure(text="Keep Logs: OFF", fg_color="gray", hover_color=("gray70", "gray30"))
            
            # Auto clear the historical logs the moment this is turned off
            self.clear_logs()
    

    def clear_logs(self):
        #Helper method to clear all system messages and forwarded requests. ignores paused requests.
        keys_to_delete = []
        
        #Iterate through our dictionary of request buttons
        for req_id, btn in self.history_buttons.items():
            # Check if this specific request is currently trapped in the proxy
            is_paused = hasattr(self.proxy, 'pending_requests') and req_id in self.proxy.pending_requests
            
            # If it's already forwarded/completed, destroy it
            if not is_paused:
                btn.destroy()
                keys_to_delete.append(req_id)
        
        #Clean up our tracking dictionary
        for req_id in keys_to_delete:
            del self.history_buttons[req_id]
            
        #Clean up generic system messages (like "Browser launched") 
        for widget in self.history_frame.winfo_children():
            if widget not in self.history_buttons.values():
                widget.destroy()

        #If the user was viewing a request that just got deleted, clear the inspector window
        if self.selected_req_id in keys_to_delete:
            self.selected_req_id = None
            self.forward_btn.configure(state="disabled")
            
            self.details_box.configure(state="normal")   
            self.details_box.delete("1.0", "end")        
            self.details_box.insert("end", "Select a request from the history to view details...") 
            self.details_box.configure(state="disabled")


def start_proxy(proxy):
    asyncio.run(proxy.start())


if __name__ == "__main__":
    proxy = AsyncProxyServer()
    proxy.log_queue = log_queue  # attach queue

    # Start proxy in background thread
    t = threading.Thread(target=start_proxy, args=(proxy,), daemon=True)
    t.start()

    # Start GUI in main thread
    app = ProxyGUI(proxy)
    app.mainloop()