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
        
    def generate_token(self, length=16):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def broadcast_listener(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', BROADCAST_PORT))
        
        while True:
            data, addr = sock.recvfrom(1024)
            msg = json.loads(data.decode())
            
            if msg['type'] == 'heartbeat':
                if msg['token'] == self.token:
                    self.last_seen[addr[0]] = time.time()
                    if self.is_manager:
                        if addr[0] not in self.workers:
                            self.workers.add(addr[0])
                            self.workers_join_order.append(addr[0])
                    else:
                        # Update manager last seen time if this is from manager
                        if addr[0] == self.manager_ip:
                            self.last_manager_seen = time.time()
                            self.manager_down_count = 0  # Reset counter
            
            elif msg['type'] == 'manager_down' and not self.is_manager:
                # First worker becomes manager
                if min(self.workers) == socket.gethostbyname(socket.gethostname()):
                    print("Manager is offline\nThis worker has now become the manager")
                    self.is_manager = True

            elif msg['type'] == 'who_is_manager' and self.is_manager:
                response = {'type': 'i_am_manager'}
                sock.sendto(json.dumps(response).encode(), addr)

            elif msg['type'] == 'manager_check' and self.is_manager:
                response = {'type': 'manager_alive', 'token': self.token}
                sock.sendto(json.dumps(response).encode(), addr)

    def heartbeat_sender(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        while True:
            msg = {
                'type': 'heartbeat',
                'token': self.token
            }
            sock.sendto(json.dumps(msg).encode(), ('<broadcast>', BROADCAST_PORT))
            time.sleep(1)

    def check_dead_nodes(self):
        while True:
            current_time = time.time()
            
            if not self.is_manager:
                # Check manager health
                if current_time - self.last_manager_seen > 30:  # 30 seconds timeout
                    if self.manager_down_count < 1:  # One final check
                        self.manager_down_count += 1
                        self.check_manager_health()
                    else:
                        # If we're the next in line, become manager
                        if self.workers_join_order and self.workers_join_order[0] == socket.gethostbyname(socket.gethostname()):
                            print("Manager is offline\nThis worker has now become the manager")
                            self.is_manager = True
                            self.manager_ip = None
                            # Remove ourselves from workers list
                            self.workers_join_order.pop(0)
            
            if self.is_manager:
                # Original manager check code
                dead_workers = []
                for worker, last_time in self.last_seen.items():
                    if current_time - last_time > 5:
                        dead_workers.append(worker)
                        if worker in self.services:
                            self.migrate_service(worker)
                
                for worker in dead_workers:
                    print(f"Worker {worker} is offline")
                    self.workers.discard(worker)
                    if worker in self.workers_join_order:
                        self.workers_join_order.remove(worker)
                    self.last_seen.pop(worker, None)
            
            time.sleep(1)

    def check_manager_health(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(60)  # Wait twice as long for final check
        
        msg = {'type': 'manager_check', 'token': self.token}
        sock.sendto(json.dumps(msg).encode(), ('<broadcast>', BROADCAST_PORT))
        
        try:
            data, addr = sock.recvfrom(1024)
            msg = json.loads(data.decode())
            if msg['type'] == 'manager_alive' and msg['token'] == self.token:
                self.last_manager_seen = time.time()
                return True
        except socket.timeout:
            return False
        finally:
            sock.close()
        return False

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
        
        while True:
            time.sleep(1)

    def join(self, manager_ip, token):
        self.manager_ip = manager_ip
        self.token = token
        self.workers = {manager_ip}
        self.last_manager_seen = time.time()
        
        threading.Thread(target=self.broadcast_listener, daemon=True).start()
        threading.Thread(target=self.heartbeat_sender, daemon=True).start()
        threading.Thread(target=self.check_dead_nodes, daemon=True).start()
        
        print("Worker Successfully Joined Cluster")
        
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
        # Try to find existing manager through broadcasts
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(3)  # Wait 3 seconds for response
        
        # Ask who is manager
        msg = {'type': 'who_is_manager'}
        sock.sendto(json.dumps(msg).encode(), ('<broadcast>', BROADCAST_PORT))
        
        try:
            data, addr = sock.recvfrom(1024)
            msg = json.loads(data.decode())
            if msg['type'] == 'i_am_manager':
                return addr[0]
        except socket.timeout:
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

    if args.bootstrap:
        # Force bootstrap as manager
        agent.bootstrap()
    elif args.join and args.token:
        # Join existing cluster
        agent.join(args.join, args.token)
    else:
        # Default behavior: look for manager, become one if none found
        print("Looking for existing manager...")
        manager_ip = agent.get_manager()
        
        if manager_ip:
            print(f"Found manager at {manager_ip}")
            if args.list_agents:
                agent.list_agents()
            elif args.deploy_service and args.path:
                if agent.is_manager:
                    agent.deploy_service(args.path)
                else:
                    print("Error: Only manager can deploy services")
        else:
            print("No manager found in network. Becoming manager...")
            agent.bootstrap()
    
    try:
        print("Agent running. Press Ctrl+C to exit.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")

if __name__ == "__main__":
    main()
