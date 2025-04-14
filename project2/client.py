import argparse
import socket
import threading
import time
import random
import string
import json
import os
import subprocess
import sys

BROADCAST_PORT = 5000
SERVICE_PORT = 5001
HEARTBEAT_INTERVAL = 15  # Seconds between heartbeats
MANAGER_TIMEOUT = (HEARTBEAT_INTERVAL * 3) + 1  # Time to wait before assuming manager is dead

class Agent:
    def __init__(self):
        self.is_manager = False
        self.manager_ip = None
        self.token = None
        self.workers = set()
        self.services = {}  # {worker_ip: service_path}
        self.last_seen = {}  # {ip: timestamp}
        self.workers_join_order = []  # List of workers in join order
        self.last_manager_seen = 0    # Last time manager was seen
        self.manager_down_count = 0   # Counter for manager down checks
        
        # Get real network IP, not localhost
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Doesn't need to be reachable
            s.connect(('10.255.255.255', 1))
            self.my_ip = s.getsockname()[0]
        except Exception:
            self.my_ip = socket.gethostbyname(socket.gethostname())
        finally:
            s.close()
        print(f"DEBUG: Initialized with IP {self.my_ip}")

    def normalize_ip(self, ip):
        if ip.startswith('127.'):
            return self.my_ip
        return ip

    def generate_token(self, length=16):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def broadcast_listener(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', BROADCAST_PORT))
        
        print(f"DEBUG: Starting listener as {'manager' if self.is_manager else 'worker'}")
        
        while True:
            try:
                data, addr = sock.recvfrom(1024)
                msg = json.loads(data.decode())
                sender_ip = addr[0]
                
                if sender_ip == self.my_ip:  # Skip our own messages
                    continue

                print(f"DEBUG: Got {msg['type']} from {sender_ip}, my role={'manager' if self.is_manager else 'worker'}")
                
                if msg['type'] == 'heartbeat' and msg.get('token') == self.token:
                    sender_ip = self.normalize_ip(sender_ip)
                    if self.is_manager:
                        # Manager handling worker heartbeat
                        self.last_seen[sender_ip] = time.time()
                        if sender_ip not in self.workers:
                            print(f"New worker joined: {sender_ip}")
                            self.workers.add(sender_ip)
                            self.workers_join_order.append(sender_ip)
                    elif sender_ip == self.manager_ip:
                        # Worker handling manager heartbeat
                        print(f"DEBUG: Got manager heartbeat")
                        self.last_manager_seen = time.time()
                        if 'workers_list' in msg:
                            old_list = self.workers_join_order.copy()
                            self.workers_join_order = msg['workers_list']
                            # Normalize IPs in the list
                            self.workers_join_order = [self.normalize_ip(ip) for ip in self.workers_join_order]
                            self.workers = set(self.workers_join_order)
                            print(f"DEBUG: My IP: {self.my_ip}")
                            print(f"DEBUG: Worker list: {self.workers_join_order}")
                            if self.my_ip in self.workers_join_order:
                                pos = self.workers_join_order.index(self.my_ip)
                                print(f"DEBUG: Found myself at position {pos}")
                            else:
                                print(f"DEBUG: IPs in list: {[type(ip) for ip in self.workers_join_order]}")
                                print(f"DEBUG: My IP type: {type(self.my_ip)}")
                
                elif msg['type'] == 'new_manager' and msg.get('token') == self.token:
                    if not self.is_manager:  # Only process if we're a worker
                        print(f"DEBUG: New manager announced: {sender_ip}")
                        self.manager_ip = sender_ip
                        self.last_manager_seen = time.time()
                        if 'workers_list' in msg:
                            self.workers_join_order = msg['workers_list']
                            self.workers = set(self.workers_join_order)
                        print(f"DEBUG: Updated manager to {sender_ip}")

                elif msg['type'] == 'who_is_manager':
                    if self.is_manager:
                        response = {'type': 'i_am_manager', 'token': self.token}
                        sock.sendto(json.dumps(response).encode(), addr)
                        print("DEBUG: Sent manager response")

            except Exception as e:
                print(f"DEBUG: Error in listener: {e}")

    def announce_manager_takeover(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        msg = {
            'type': 'new_manager',
            'token': self.token,
            'workers_list': self.workers_join_order
        }
        
        try:
            sock.sendto(json.dumps(msg).encode(), ('<broadcast>', BROADCAST_PORT))
            print("DEBUG: Announced manager takeover")
        except Exception as e:
            print(f"DEBUG: Error announcing takeover: {e}")
        finally:
            sock.close()

    def heartbeat_sender(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        while True:
            msg = {
                'type': 'heartbeat',
                'token': self.token
            }
            
            if self.is_manager:
                msg['workers_list'] = self.workers_join_order
            
            try:
                sock.sendto(json.dumps(msg).encode(), ('<broadcast>', BROADCAST_PORT))
                print(f"DEBUG: Sent heartbeat as {'manager' if self.is_manager else 'worker'}")
                print(f"DEBUG: Heartbeat message: {msg}")
            except Exception as e:
                print(f"DEBUG: Error sending heartbeat: {e}")
                print(f"DEBUG: Error details:", str(e))
            
            time.sleep(HEARTBEAT_INTERVAL)

    def check_dead_nodes(self):
        while True:
            current_time = time.time()
            
            if self.is_manager:
                # Manager checks for dead workers
                dead_workers = []
                for worker_ip, last_time in list(self.last_seen.items()):
                    if worker_ip != self.my_ip:
                        if current_time - last_time > HEARTBEAT_INTERVAL + 5:
                            print(f"Worker {worker_ip} appears dead - last seen {current_time - last_time:.1f}s ago")
                            dead_workers.append(worker_ip)
                            if worker_ip in self.services:
                                self.migrate_service(worker_ip)
                
                for worker in dead_workers:
                    print(f"Removing dead worker: {worker}")
                    self.workers.discard(worker)
                    if worker in self.workers_join_order:
                        self.workers_join_order.remove(worker)
                    self.last_seen.pop(worker, None)
            
            else:  # Worker checking manager
                time_since_manager = current_time - self.last_manager_seen
                if time_since_manager > MANAGER_TIMEOUT:
                    if len(self.workers_join_order) > 0:  # Make sure list isn't empty
                        if self.my_ip in self.workers_join_order:
                            my_position = self.workers_join_order.index(self.my_ip)
                            print(f"DEBUG: Manager dead, I am position {my_position} in line")
                            if my_position == 0:  # We're next in line
                                print(f"Taking over as manager after {time_since_manager:.1f}s timeout")
                                self.is_manager = True
                                self.manager_ip = None
                                self.workers_join_order = self.workers_join_order[1:]  # Remove ourselves
                                self.workers = set(self.workers_join_order)
                                # Announce takeover to other nodes
                                self.announce_manager_takeover()
                                print(f"DEBUG: I am now manager. Workers: {self.workers_join_order}")
                                return  # Exit check_dead_nodes and restart as manager
                            else:
                                print(f"DEBUG: Not first in line, waiting for {self.workers_join_order[0]}")
            
            time.sleep(1)

    def migrate_service(self, dead_worker):
        if dead_worker in self.services:
            service_path = self.services[dead_worker]
            available_workers = list(self.workers - {dead_worker})
            if available_workers:
                new_worker = random.choice(available_workers)
                self.deploy_service(service_path, new_worker)
                print(f"Migrated {service_path} to worker {new_worker}")
                self.services[new_worker] = service_path
                del self.services[dead_worker]

    def deploy_service(self, path, worker_ip=None):
        if not worker_ip:
            worker_ip = random.choice(list(self.workers))
        
        # Simple service that continuously prints "I'm alive!"
        service_code = '''
import time
while True:
    print("I'm alive!")
    time.sleep(1)
'''
        
        # Create a temporary file for the service
        temp_path = f'/tmp/service_{int(time.time())}.py'
        with open(temp_path, 'w') as f:
            f.write(service_code)
        
        # Execute the service using subprocess
        subprocess.Popen(['python3', temp_path])
        
        self.services[worker_ip] = temp_path
        print(f"Deployed service on {worker_ip}")

    def bootstrap(self):
        self.is_manager = True
        self.token = self.generate_token()
        print(f"Worker Join Token: {self.token}")
        
        threading.Thread(target=self.broadcast_listener, daemon=True).start()
        threading.Thread(target=self.heartbeat_sender, daemon=True).start()
        threading.Thread(target=self.check_dead_nodes, daemon=True).start()
        
        self.announce_manager_takeover()  # Announce when becoming initial manager
        
        while True:
            time.sleep(1)

    def join(self, manager_ip, token):
        print(f"DEBUG: Joining cluster under manager {manager_ip}")
        self.is_manager = False
        self.manager_ip = manager_ip
        self.token = token
        self.workers = set()
        self.last_seen = {}
        self.last_manager_seen = time.time()
        self.workers_join_order = []  # Will be populated by manager's heartbeat
        
        # Start threads
        threading.Thread(target=self.broadcast_listener, daemon=True).start()
        threading.Thread(target=self.heartbeat_sender, daemon=True).start()
        threading.Thread(target=self.check_dead_nodes, daemon=True).start()
        
        print(f"DEBUG: Started as worker under manager {manager_ip}")
        
        while True:
            time.sleep(1)

    def list_agents(self):
        if self.is_manager:
            print(f"Manager: {socket.gethostbyname(socket.gethostname())}")
            print("Workers:")
            for worker in self.workers:
                print(worker)
        else:
            print("Error: Only manager can list agents")

    def get_manager(self):
        print("DEBUG: Looking for existing manager...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(3)
        
        msg = {'type': 'who_is_manager'}
        sock.sendto(json.dumps(msg).encode(), ('<broadcast>', BROADCAST_PORT))
        
        try:
            data, addr = sock.recvfrom(1024)
            msg = json.loads(data.decode())
            if msg['type'] == 'i_am_manager' and 'token' in msg:
                print(f"DEBUG: Found manager at {addr[0]}")
                self.token = msg['token']  # Set token from manager response
                return addr[0]
        except socket.timeout:
            print("DEBUG: No manager response received")
            return None
        finally:
            sock.close()
        return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bootstrap', action='store_true', help='Force bootstrap as manager')
    parser.add_argument('--join', type=str, help='Join existing cluster using manager IP')
    parser.add_argument('--token', type=str, help='Authentication token for joining')
    parser.add_argument('--list-agents', action='store_true', help='List all agents in cluster')
    parser.add_argument('--deploy-service', action='store_true', help='Deploy a service')
    parser.add_argument('--path', type=str, help='Path to service file')
    args = parser.parse_args()

    agent = Agent()
    agent.is_manager = False  # Default to worker role

    if args.bootstrap:
        agent.bootstrap()
    elif args.join and args.token:
        agent.join(args.join, args.token)
    else:
        manager_ip = agent.get_manager()
        if manager_ip:
            print(f"Found manager at {manager_ip}")
            # Join as worker when manager found
            agent.join(manager_ip, agent.token)
        else:
            print("No manager found. Becoming manager...")
            agent.bootstrap()

    try:
        print("Agent running. Press Ctrl+C to exit.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")

if __name__ == "__main__":
    main()
