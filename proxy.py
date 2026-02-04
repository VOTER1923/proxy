import socket
import threading
import base64
import select
import time
import json
import os
import csv
from collections import defaultdict
from cryptography.fernet import Fernet

# ============================
# CONFIGURATION
# ============================

LISTEN_HOST = "192.168.124.9"
LISTEN_PORT = 8080
MONITOR_PORT = 8081  # Port for remote monitoring
CACHE_TTL = 180  # Cache entries expire after 3 minutes
SESSION_TIMEOUT = 180  # Session timeout (3 minutes of inactivity before device can be replaced)
MAX_CACHED_CONNECTIONS = 100
CACHE_FILE = os.path.join(os.path.dirname(__file__), "proxy_cache.json")  # File to persist cache
CACHE_SAVE_INTERVAL = 60  # Save cache every 60 seconds
USERS_FILE = os.path.join(os.path.dirname(__file__), "proxy_users.csv")  # Encrypted users file
ENCRYPTION_KEY_FILE = os.path.join(os.path.dirname(__file__), ".proxy_key")  # Encryption key file
LOGIN_LOG_FILE = os.path.join(os.path.dirname(__file__), "proxy_login.log")  # Login log file
BANDWIDTH_LIMIT_MBPS = 30  # Global bandwidth limit in Mbps (30 Mbps = 3.75 MB/s)
PROXY_ACCESS_START_HOUR = 9  # Allow connections from 9am
PROXY_ACCESS_START_MINUTE = 0
PROXY_ACCESS_END_HOUR = 15  # Until 3pm
PROXY_ACCESS_END_MINUTE = 15

# Dictionary of valid users and passwords (loaded from encrypted CSV file on startup)
PROXY_USERS = {}

# Pre-compute auth tokens for validation (populated after loading users)
proxy_auth_tokens = {}

# Track active user sessions (one device per user)
user_sessions = {}  # {username: (device_ip, timestamp, socket_obj, is_active)}

# Track which sessions have been logged to avoid duplicate logs
logged_sessions = set()  # {(username, device_ip, timestamp)}


# ============================
# ENCRYPTION UTILITIES
# ============================

def get_or_create_key():
    """Get encryption key from file, or create one if it doesn't exist."""
    if os.path.exists(ENCRYPTION_KEY_FILE):
        with open(ENCRYPTION_KEY_FILE, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(ENCRYPTION_KEY_FILE, 'wb') as f:
            f.write(key)
        os.chmod(ENCRYPTION_KEY_FILE, 0o600)  # Restrict to user only
        return key

encryption_key = get_or_create_key()
cipher = Fernet(encryption_key)


def encrypt_text(text):
    """Encrypt text using Fernet."""
    return cipher.encrypt(text.encode()).decode()


def decrypt_text(encrypted_text):
    """Decrypt text using Fernet."""
    try:
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None


def save_users_to_csv():
    """Save users to encrypted CSV file."""
    try:
        with open(USERS_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['username', 'password_encrypted'])
            for username, password in PROXY_USERS.items():
                encrypted_password = encrypt_text(password)
                writer.writerow([username, encrypted_password])
        print(f"[*] Saved {len(PROXY_USERS)} users to encrypted CSV file")
    except Exception as e:
        print(f"[!] Error saving users to CSV: {e}")


def load_users_from_csv():
    """Load users from encrypted CSV file."""
    if not os.path.exists(USERS_FILE):
        print("[*] No user CSV file found, using default users")
        return False
    
    try:
        with open(USERS_FILE, 'r') as f:
            reader = csv.reader(f)
            next(reader)  # Skip header
            PROXY_USERS.clear()
            for row in reader:
                if len(row) >= 2:
                    username, encrypted_password = row[0], row[1]
                    decrypted_password = decrypt_text(encrypted_password)
                    if decrypted_password:
                        PROXY_USERS[username] = decrypted_password
        
        # Rebuild auth tokens
        rebuild_auth_tokens()
        print(f"[*] Loaded {len(PROXY_USERS)} users from encrypted CSV file")
        return True
    except Exception as e:
        print(f"[!] Error loading users from CSV: {e}")
        return False


def rebuild_auth_tokens():
    """Rebuild auth tokens from PROXY_USERS."""
    proxy_auth_tokens.clear()
    for user, passwd in PROXY_USERS.items():
        proxy_auth_tokens[base64.b64encode(f"{user}:{passwd}".encode()).decode()] = user


# ============================
# BANDWIDTH RATE LIMITER
# ============================

class BandwidthLimiter:
    """Token bucket rate limiter for global bandwidth control."""
    def __init__(self, max_bytes_per_second):
        self.max_bytes_per_second = max_bytes_per_second
        self.tokens = max_bytes_per_second  # Start with full bucket
        self.last_refill = time.time()
        self.lock = threading.Lock()
    
    def acquire(self, num_bytes):
        """Block until num_bytes tokens are available, then consume them."""
        while True:
            with self.lock:
                now = time.time()
                elapsed = now - self.last_refill
                
                # Refill tokens based on elapsed time
                refill_amount = elapsed * self.max_bytes_per_second
                self.tokens = min(self.max_bytes_per_second, self.tokens + refill_amount)
                self.last_refill = now
                
                # If we have enough tokens, consume them and return
                if self.tokens >= num_bytes:
                    self.tokens -= num_bytes
                    return
            
            # Not enough tokens, sleep and try again
            time.sleep(0.01)


# Initialize rate limiter: 30 Mbps = 3,750,000 bytes/second
rate_limiter = BandwidthLimiter(int(BANDWIDTH_LIMIT_MBPS * 1_000_000 / 8))


def log_login(username, device_ip, status="LOGIN"):
    """Log user login/logout events to file."""
    try:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"{timestamp} | {status} | User: {username} | Device: {device_ip}\n"
        with open(LOGIN_LOG_FILE, 'a') as f:
            f.write(log_entry)
        print(f"[*] Logged: {status} - {username} from {device_ip}")
    except Exception as e:
        print(f"[!] Error writing login log: {e}")


def is_proxy_access_allowed():
    """Check if current time is within allowed proxy access hours."""
    import datetime
    now = datetime.datetime.now()
    current_time = (now.hour, now.minute)
    start_time = (PROXY_ACCESS_START_HOUR, PROXY_ACCESS_START_MINUTE)
    end_time = (PROXY_ACCESS_END_HOUR, PROXY_ACCESS_END_MINUTE)
    
    if start_time <= current_time < end_time:
        return True
    return False


def check_user_session(username, device_ip, current_socket):
    """Enforce one device per user. Every connection requires fresh authentication."""
    global user_sessions, logged_sessions
    
    if username in user_sessions:
        existing_ip, existing_time, existing_socket, is_active = user_sessions[username]
        time_elapsed = time.time() - existing_time
        
        # Same device - ALWAYS require fresh login but don't log again
        if existing_ip == device_ip:
            user_sessions[username] = (device_ip, time.time(), current_socket, True)
            return True, f"Fresh login required for {username} from {device_ip}"
        
        # Different device - check if previous session timed out
        if time_elapsed >= SESSION_TIMEOUT:
            # Previous session expired, allow new device
            try:
                existing_socket.close()
            except:
                pass
            print(f"[*] Previous session for {username} expired after {time_elapsed:.0f}s inactivity")
            log_login(username, existing_ip, "LOGOUT_TIMEOUT")
            logged_sessions.discard((username, existing_ip, existing_time))
            
            # New session on new device
            user_sessions[username] = (device_ip, time.time(), current_socket, True)
            session_key = (username, device_ip, time.time())
            log_login(username, device_ip, "LOGIN_NEW_DEVICE")
            logged_sessions.add(session_key)
            return True, f"New device allowed for {username} (previous session timed out)"
        else:
            # Previous session still active - block this new device
            remaining = SESSION_TIMEOUT - time_elapsed
            response = b"HTTP/1.1 407 Proxy Authentication Required\r\n"
            response += b"Proxy-Authenticate: Basic realm=\"Device Already Connected - Wait " + f"{remaining:.0f}s".encode() + b"\"\r\n"
            response += b"Connection: close\r\n"
            response += b"\r\n"
            current_socket.sendall(response)
            current_socket.close()
            print(f"[!] User {username} already active on {existing_ip}. Blocking device {device_ip} for {remaining:.0f}s")
            return False, f"User {username} already connected on another device"
    else:
        # New session
        session_time = time.time()
        user_sessions[username] = (device_ip, session_time, current_socket, True)
        session_key = (username, device_ip, session_time)
        log_login(username, device_ip, "LOGIN")
        logged_sessions.add(session_key)
        return True, f"New session for {username} from {device_ip}"


# ============================
# CACHING SYSTEM
# ============================

class CacheManager:
    """Manages connection pooling and DNS caching with persistent storage."""
    
    def __init__(self, ttl=CACHE_TTL, max_connections=MAX_CACHED_CONNECTIONS, cache_file=CACHE_FILE):
        self.ttl = ttl
        self.max_connections = max_connections
        self.cache_file = cache_file
        self.connection_cache = {}  # {(host, port): (socket, timestamp)}
        self.dns_cache = {}  # {hostname: (ip, timestamp)}
        self.page_cache = {}  # {(host, port, path): [(response_data, timestamp), ...]}  - list of versions
        self.active_clients = {}  # {client_address: (user, timestamp)} - track active connections
        self.lock = threading.Lock()
        self.save_thread = None
        self.should_exit = False
        
        # Load cache from disk on startup
        self.load_cache_from_disk()
    
    def load_cache_from_disk(self):
        """Load cached DNS entries and pages from disk."""
        if not os.path.exists(self.cache_file):
            return
        
        try:
            with open(self.cache_file, 'r') as f:
                data = json.load(f)
                with self.lock:
                    # Restore DNS cache
                    current_time = time.time()
                    for hostname, (ip, timestamp) in data.get('dns_cache', {}).items():
                        # Only restore if not expired
                        if current_time - timestamp < self.ttl:
                            self.dns_cache[hostname] = (ip, timestamp)
                    # Restore page cache (pages never expire, store as list of versions)
                    for page_key, versions in data.get('page_cache', {}).items():
                        try:
                            key = tuple(json.loads(page_key))
                            if isinstance(versions, list):
                                self.page_cache[key] = versions
                            else:
                                # Handle old format (single version)
                                self.page_cache[key] = [versions]
                        except:
                            pass
                    print(f"[*] Loaded {len(self.dns_cache)} DNS cache entries and {len(self.page_cache)} page cache entries from disk")
        except Exception as e:
            print(f"[!] Error loading cache from disk: {e}")
    
    def save_cache_to_disk(self):
        """Save cache to disk."""
        try:
            with self.lock:
                # Save DNS cache and page cache (convert tuple keys to strings for JSON)
                page_cache_serializable = {
                    json.dumps(key): (value, timestamp) 
                    for key, (value, timestamp) in self.page_cache.items()
                }
                data = {
                    'dns_cache': dict(self.dns_cache),
                    'page_cache': page_cache_serializable,
                    'timestamp': time.time()
                }
            
            with open(self.cache_file, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"[*] Saved cache to disk ({len(self.dns_cache)} DNS entries, {len(self.page_cache)} page entries)")
        except Exception as e:
            print(f"[!] Error saving cache to disk: {e}")
    
    def _auto_save_thread(self):
        """Background thread that periodically saves cache."""
        while not self.should_exit:
            time.sleep(CACHE_SAVE_INTERVAL)
            if not self.should_exit:
                self.save_cache_to_disk()
    
    def start_auto_save(self):
        """Start the background thread for periodic cache saves."""
        self.should_exit = False
        self.save_thread = threading.Thread(target=self._auto_save_thread, daemon=True)
        self.save_thread.start()
    
    def stop_auto_save(self):
        """Stop the background save thread."""
        self.should_exit = True
        if self.save_thread:
            self.save_thread.join(timeout=2)
    
    def get_cached_connection(self, host, port):
        """Retrieve a cached connection if available and valid."""
        with self.lock:
            key = (host, port)
            if key in self.connection_cache:
                sock, timestamp = self.connection_cache[key]
                if time.time() - timestamp < self.ttl:
                    return sock
                else:
                    # Connection expired, close and remove
                    try:
                        sock.close()
                    except:
                        pass
                    del self.connection_cache[key]
        return None
    
    def cache_connection(self, host, port, sock):
        """Cache a connection for future reuse."""
        with self.lock:
            # Clean up expired entries if cache is full
            if len(self.connection_cache) >= self.max_connections:
                self._cleanup_expired_connections()
            
            key = (host, port)
            self.connection_cache[key] = (sock, time.time())
    
    def _cleanup_expired_connections(self):
        """Remove expired connections from cache."""
        current_time = time.time()
        expired_keys = [
            key for key, (sock, timestamp) in self.connection_cache.items()
            if current_time - timestamp >= self.ttl
        ]
        for key in expired_keys:
            try:
                self.connection_cache[key][0].close()
            except:
                pass
            del self.connection_cache[key]
    
    def get_cached_dns(self, hostname):
        """Retrieve a cached DNS lookup if available and valid."""
        with self.lock:
            if hostname in self.dns_cache:
                ip, timestamp = self.dns_cache[hostname]
                if time.time() - timestamp < self.ttl:
                    return ip
                else:
                    del self.dns_cache[hostname]
        return None
    
    def cache_dns(self, hostname, ip):
        """Cache a DNS lookup result."""
        with self.lock:
            self.dns_cache[hostname] = (ip, time.time())
    
    def get_cached_page(self, host, port, path):
        """Retrieve the newest cached page version (never expires)."""
        with self.lock:
            key = (host, port, path)
            if key in self.page_cache:
                versions = self.page_cache[key]
                if versions:
                    # Return the newest version (last in list)
                    response, timestamp = versions[-1]
                    print(f"[*] Found cached page for {host}:{port}{path}")
                    return response
        return None
    
    def cache_page(self, host, port, path, response_data):
        """Cache a page response. Keep only the newest and 2nd newest versions."""
        with self.lock:
            key = (host, port, path)
            
            # Check if page already cached
            if key in self.page_cache:
                versions = self.page_cache[key]
                if versions:
                    newest_response, _ = versions[-1]
                    # Compare with newest cached version
                    if newest_response == response_data:
                        print(f"[*] Page unchanged for {host}:{port}{path} - keeping cached version")
                        return  # Don't update if same as newest
                    else:
                        print(f"[*] Page updated for {host}:{port}{path} - new version added to cache")
                # Add new version
                versions.append((response_data, time.time()))
                # Keep only newest and 2nd newest (delete oldest if more than 2)
                if len(versions) > 2:
                    deleted = versions.pop(0)
                    print(f"[*] Deleted oldest version for {host}:{port}{path}")
            else:
                # First version of this page
                self.page_cache[key] = [(response_data, time.time())]
                print(f"[*] Cached new page: {host}:{port}{path}")
    
    def clear_cache(self):
        """Clear all cached connections and DNS entries."""
        with self.lock:
            for sock, _ in self.connection_cache.values():
                try:
                    sock.close()
                except:
                    pass
            self.connection_cache.clear()
            self.dns_cache.clear()
            self.page_cache.clear()
        # Save empty cache to disk
        self.save_cache_to_disk()


# Initialize global cache manager
cache_manager = CacheManager()


# ============================
# HTTPS PROXY HANDLER
# ============================

def handle_client(client_sock, addr):
    """Handle incoming HTTPS proxy connections."""
    authenticated_user = None
    # Read the CONNECT request line
    request = b""
    try:
        while b"\r\n\r\n" not in request:
            chunk = client_sock.recv(1024)
            if not chunk:
                return
            request += chunk
        
        # Parse the request
        request_str = request.decode('utf-8', errors='ignore')
        lines = request_str.split("\r\n")
        first_line = lines[0]
        
        # Check if it's a CONNECT request
        if not first_line.startswith("CONNECT"):
            client_sock.close()
            return
        
        # Parse host and port
        parts = first_line.split()
        if len(parts) < 2:
            client_sock.close()
            return
        
        host_port = parts[1]
        try:
            host, port = host_port.split(":")
            port = int(port)
        except:
            client_sock.close()
            return
        
        # Check authentication
        auth_header = None
        for line in lines[1:]:
            if line.lower().startswith("proxy-authorization:"):
                auth_header = line.split(":", 1)[1].strip()
                break
        
        if not auth_header or not auth_header.startswith("Basic "):
            response = b"HTTP/1.1 407 Proxy Authentication Required\r\n"
            response += b"Proxy-Authenticate: Basic realm=\"Home PC Proxy\"\r\n"
            response += b"Connection: close\r\n"
            response += b"\r\n"
            client_sock.sendall(response)
            client_sock.close()
            return
        
        token = auth_header.split(" ", 1)[1].strip() if " " in auth_header else ""
        
        # Validate token and get username
        if token not in proxy_auth_tokens:
            response = b"HTTP/1.1 407 Proxy Authentication Required\r\n"
            response += b"Proxy-Authenticate: Basic realm=\"Home PC Proxy\"\r\n"
            response += b"Connection: close\r\n"
            response += b"\r\n"
            client_sock.sendall(response)
            client_sock.close()
            return
        
        authenticated_user = proxy_auth_tokens[token]
        device_ip = addr[0]
        print(f"[*] Authenticated user: {authenticated_user} from device {device_ip}")
        
        # Check if proxy access is allowed at this time
        if not is_proxy_access_allowed():
            current_time = time.strftime("%H:%M")
            response = f"HTTP/1.1 403 Forbidden\r\n"
            response += f"Connection: close\r\n"
            response += f"\r\n"
            response += f"Proxy access is only allowed from {PROXY_ACCESS_START_HOUR}:{PROXY_ACCESS_START_MINUTE:02d} to {PROXY_ACCESS_END_HOUR}:{PROXY_ACCESS_END_MINUTE:02d}. Current time: {current_time}"
            client_sock.sendall(response.encode())
            client_sock.close()
            print(f"[!] Access denied for {authenticated_user} - outside allowed hours ({current_time})")
            return
        
        # Check and manage user sessions (one device per user with 3-minute timeout)
        with cache_manager.lock:
            allowed, msg = check_user_session(authenticated_user, device_ip, client_sock)
            print(f"[*] {msg}")
            if not allowed:
                # Session check already sent error response and closed socket
                return
            cache_manager.active_clients[addr] = (authenticated_user, time.time())
        
        try:
            remote_sock = cache_manager.get_cached_connection(host, port)
            
            # If not cached, create new connection
            if remote_sock is None:
                # Check DNS cache first
                resolved_ip = cache_manager.get_cached_dns(host)
                
                try:
                    if resolved_ip:
                        print(f"[*] Using cached DNS for {host} -> {resolved_ip}")
                        remote_sock = socket.create_connection((resolved_ip, port), timeout=10)
                    else:
                        remote_sock = socket.create_connection((host, port), timeout=10)
                        # Cache the DNS resolution
                        try:
                            resolved_ip = socket.gethostbyname(host)
                            cache_manager.cache_dns(host, resolved_ip)
                            print(f"[*] Cached DNS: {host} -> {resolved_ip}")
                        except:
                            pass
                except Exception as e:
                    response = f"HTTP/1.1 502 Bad Gateway\r\n\r\n".encode()
                    client_sock.sendall(response)
                    client_sock.close()
                    return
            else:
                print(f"[*] Using cached connection to {host}:{port}")
            
            # Send 200 response
            response = b"HTTP/1.1 200 Connection Established\r\n\r\n"
            client_sock.sendall(response)
            
            # Tunnel data bidirectionally (pass authenticated_user to check if deleted)
            tunnel(client_sock, remote_sock, host, port, authenticated_user)
        
        except Exception as e:
            print(f"[Error] {e}")
        finally:
            # Mark session as inactive on disconnect and log only once
            if authenticated_user:
                device_ip = addr[0]
                with cache_manager.lock:
                    if addr in cache_manager.active_clients:
                        del cache_manager.active_clients[addr]
                    # Mark session as inactive but keep it for 3-minute timeout
                    if authenticated_user in user_sessions:
                        stored_ip, stored_time, stored_socket, is_active = user_sessions[authenticated_user]
                        if stored_ip == device_ip and is_active:  # Only log if was active
                            user_sessions[authenticated_user] = (stored_ip, stored_time, stored_socket, False)
                            session_key = (authenticated_user, device_ip, stored_time)
                            if session_key in logged_sessions:
                                log_login(authenticated_user, device_ip, "DISCONNECT")
                                logged_sessions.discard(session_key)
            try:
                client_sock.close()
            except:
                pass
    
    except Exception as e:
        print(f"[Error in handle_client] {e}")
        try:
            client_sock.close()
        except:
            pass


def tunnel(client, remote, host, port, authenticated_user):
    """Tunnel data bidirectionally and check if user still exists. Cache connection if reusable."""
    connection_reusable = True
    try:
        while True:
            # Periodically check if user still exists (every iteration)
            if authenticated_user not in PROXY_USERS:
                print(f"[!] User {authenticated_user} was deleted. Disconnecting.")
                log_login(authenticated_user, "0.0.0.0", "DISCONNECT_USER_DELETED_MID_SESSION")
                return
            
            readable, _, exceptional = select.select([client, remote], [], [client, remote], 1)
            
            if exceptional:
                break
            
            for sock in readable:
                try:
                    data = sock.recv(4096)
                    if not data:
                        return
                    
                    # Apply bandwidth rate limiting
                    rate_limiter.acquire(len(data))
                    
                    if sock is client:
                        remote.sendall(data)
                    else:
                        client.sendall(data)
                except:
                    connection_reusable = False
                    return
    except:
        connection_reusable = False
    finally:
        try:
            client.close()
        except:
            pass
        
        # Cache the remote connection for reuse if it's still valid
        if connection_reusable:
            try:
                # Test if connection is still alive before caching
                remote.settimeout(0.1)
                remote.send(b"")
                remote.settimeout(None)
                cache_manager.cache_connection(host, port, remote)
                print(f"[*] Cached connection for {host}:{port}")
            except:
                try:
                    remote.close()
                except:
                    pass
        else:
            try:
                remote.close()
            except:
                pass


def start_monitor_server():
    """Start a monitoring server for remote cache/activity viewing."""
    monitor_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    monitor_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        monitor_sock.bind((LISTEN_HOST, MONITOR_PORT))
        monitor_sock.listen(1)
        print(f"[*] Monitor server started on {LISTEN_HOST}:{MONITOR_PORT}")
    except Exception as e:
        print(f"[!] Failed to start monitor server: {e}")
        return
    
    while True:
        try:
            client_sock, addr = monitor_sock.accept()
            print(f"[*] Monitor connection from {addr[0]}:{addr[1]}")
            threading.Thread(target=handle_monitor_request, args=(client_sock,), daemon=True).start()
        except Exception as e:
            print(f"[!] Monitor error: {e}")


def handle_monitor_request(client_sock):
    """Handle a monitoring request."""
    try:
        # Read full request
        request = client_sock.recv(1024).decode('utf-8', errors='ignore').strip()
        parts = request.split()
        
        if not parts:
            response = "No command received.\n"
            client_sock.sendall(response.encode())
            return
        
        command = parts[0].upper()
        
        if command == "STATUS":
            # Build status response
            with cache_manager.lock:
                dns_count = len(cache_manager.dns_cache)
                page_count = len(cache_manager.page_cache)
                conn_count = len(cache_manager.connection_cache)
                active_count = len(cache_manager.active_clients)
            
            response = f"""PROXY STATUS
============
DNS Cache Entries: {dns_count}
Cached Pages: {page_count}
Active Connections: {conn_count}
Active Clients: {active_count}
Cache File: {CACHE_FILE}
"""
            client_sock.sendall(response.encode())
        
        elif command == "CLIENTS":
            # List active clients
            with cache_manager.lock:
                clients_info = list(cache_manager.active_clients.items())
            
            if not clients_info:
                response = "No active clients.\n"
            else:
                response = "ACTIVE CLIENTS\n==============\n"
                for addr, (user, timestamp) in clients_info:
                    age = int(time.time() - timestamp)
                    response += f"{addr[0]}:{addr[1]} - User: {user} (connected {age}s ago)\n"
            
            client_sock.sendall(response.encode())
        
        elif command == "ADDUSER":
            if len(parts) < 3:
                response = "Usage: ADDUSER username password\n"
                client_sock.sendall(response.encode())
                return
            
            username = parts[1]
            password = parts[2]
            
            if username in PROXY_USERS:
                response = f"User '{username}' already exists.\n"
            else:
                PROXY_USERS[username] = password
                # Rebuild auth tokens
                proxy_auth_tokens.clear()
                for user, passwd in PROXY_USERS.items():
                    proxy_auth_tokens[base64.b64encode(f"{user}:{passwd}".encode()).decode()] = user
                save_users_to_csv()  # Save to encrypted CSV
                response = f"User '{username}' added successfully with password '{password}'.\n"
                print(f"[*] Added user: {username}:{password}")
            
            client_sock.sendall(response.encode())
        
        elif command == "DELUSER":
            if len(parts) < 2:
                response = "Usage: DELUSER username\n"
                client_sock.sendall(response.encode())
                return
            
            username = parts[1]
            
            if username not in PROXY_USERS:
                response = f"User '{username}' does not exist.\n"
            else:
                del PROXY_USERS[username]
                # Rebuild auth tokens
                proxy_auth_tokens.clear()
                for user, passwd in PROXY_USERS.items():
                    proxy_auth_tokens[base64.b64encode(f"{user}:{passwd}".encode()).decode()] = user
                save_users_to_csv()  # Save to encrypted CSV
                
                # Disconnect any active sessions for this user
                global user_sessions
                if username in user_sessions:
                    stored_ip, _, stored_socket, _ = user_sessions[username]
                    try:
                        stored_socket.close()
                        print(f"[*] Forcefully disconnected active session for deleted user: {username} from {stored_ip}")
                        log_login(username, stored_ip, "DISCONNECT_USER_DELETED")
                    except:
                        pass
                    del user_sessions[username]
                
                response = f"User '{username}' deleted successfully and disconnected if active.\n"
                print(f"[*] Deleted user: {username}")
            
            client_sock.sendall(response.encode())
        
        elif command == "LISTUSERS":
            response = "VALID PROXY USERS\n=================\n"
            with cache_manager.lock:
                for user, passwd in PROXY_USERS.items():
                    response += f"{user}:{passwd}\n"
            
            client_sock.sendall(response.encode())
        
        elif command == "CACHE":
            # Send full cache data as JSON
            with cache_manager.lock:
                data = {
                    'dns_cache': dict(cache_manager.dns_cache),
                    'page_cache_count': len(cache_manager.page_cache),
                    'connection_count': len(cache_manager.connection_cache),
                    'timestamp': time.time()
                }
            client_sock.sendall(json.dumps(data, indent=2).encode())
        
        elif command == "LOGINLOG":
            # Display login log
            if os.path.exists(LOGIN_LOG_FILE):
                try:
                    with open(LOGIN_LOG_FILE, 'r') as f:
                        log_content = f.read()
                    response = "LOGIN/LOGOUT LOG\n================\n" + log_content
                except Exception as e:
                    response = f"Error reading login log: {e}\n"
            else:
                response = "No login log file found.\n"
            client_sock.sendall(response.encode())
        
        elif command == "HELP":
            response = """PROXY MONITOR COMMANDS
======================
STATUS        - Show proxy status
CLIENTS       - List active connected clients
ADDUSER u p   - Add new user (username password)
DELUSER u     - Delete user (username)
LISTUSERS     - List all valid users
CACHE         - Show cache data (JSON)
LOGINLOG      - Show login/logout history
HELP          - Show this help message
"""
            client_sock.sendall(response.encode())
        
        else:
            response = f"Unknown command: {command}\nType 'HELP' for available commands.\n"
            client_sock.sendall(response.encode())
    
    except Exception as e:
        print(f"[!] Monitor request error: {e}")
    finally:
        try:
            client_sock.close()
        except:
            pass



def start_proxy():
    """Start the HTTPS proxy server."""
    # Load users from encrypted CSV file on startup
    if not load_users_from_csv():
        # If no CSV exists, save default users
        save_users_to_csv()
    
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((LISTEN_HOST, LISTEN_PORT))
    server_sock.listen(5)
    
    print(f"[*] HTTPS Proxy Server with Persistent Caching")
    print(f"[*] Listening on {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"[*] Monitor listening on {LISTEN_HOST}:{MONITOR_PORT}")
    print(f"[*] Cache TTL: {CACHE_TTL} seconds")
    print(f"[*] Cache file: {CACHE_FILE}")
    print(f"[*] Users file: {USERS_FILE} (encrypted)")
    print(f"[*] Auto-save interval: {CACHE_SAVE_INTERVAL} seconds")
    print(f"[*] Max cached connections: {MAX_CACHED_CONNECTIONS}")
    print(f"[*] Valid users:")
    for user, passwd in PROXY_USERS.items():
        print(f"     - {user}:{passwd}")
    print(f"[*] Ready to accept connections...")
    
    # Start auto-save thread
    cache_manager.start_auto_save()
    
    # Start monitor server
    monitor_thread = threading.Thread(target=start_monitor_server, daemon=True)
    monitor_thread.start()
    
    try:
        while True:
            client_sock, addr = server_sock.accept()
            print(f"[*] Connection from {addr[0]}:{addr[1]}")
            threading.Thread(target=handle_client, args=(client_sock, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        cache_manager.stop_auto_save()
        cache_manager.save_cache_to_disk()
    finally:
        server_sock.close()


if __name__ == "__main__":
    start_proxy()
