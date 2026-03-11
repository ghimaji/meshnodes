#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <chrono>
#include <cstring>
#include <sstream>
#include <iomanip>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef int socklen_t;
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #define SOCKET int
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define closesocket close
#endif

// Simple SHA-256 hash function for password verification
#include <openssl/sha.h>

class MeshNode {
private:
    struct Peer {
        std::string nodeId;
        std::string address;
        int port;
        int listenPort;  // The port this peer is listening on
        SOCKET socket;
        bool connected;
        bool authenticated;
        time_t lastSeen;
        time_t lastHeartbeat;
    };

     const int HEARTBEAT_INTERVAL = 5;  // seconds
     const int HEARTBEAT_TIMEOUT = 15;  // seconds

    int listenPort;
    SOCKET listenSocket;
    std::map<std::string, Peer> peers;
    std::mutex peersMutex;
    bool running;
    std::string nodeId;
    std::string passwordHash;

    void initSockets() {
#ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            throw std::runtime_error("WSAStartup failed");
        }
#endif
    }

    void cleanupSockets() {
#ifdef _WIN32
        WSACleanup();
#endif
    }

    std::string sha256(const std::string& str) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, str.c_str(), str.length());
        SHA256_Final(hash, &sha256);
        
        std::stringstream ss;
        for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        return ss.str();
    }

    std::string generateNodeId() {
        auto now = std::chrono::system_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
        return "Node_" + std::to_string(ms % 10000);
    }

    void startListening() {
        listenSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (listenSocket == INVALID_SOCKET) {
            throw std::runtime_error("Failed to create listen socket");
        }

        int opt = 1;
        setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(listenPort);

        if (bind(listenSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            closesocket(listenSocket);
            throw std::runtime_error("Failed to bind socket");
        }

        if (listen(listenSocket, 10) == SOCKET_ERROR) {
            closesocket(listenSocket);
            throw std::runtime_error("Failed to listen on socket");
        }

        std::cout << "[" << nodeId << "] Listening on port " << listenPort << std::endl;
    }

    void acceptConnections() {
        while (running) {
            sockaddr_in clientAddr;
            socklen_t clientLen = sizeof(clientAddr);
            
            SOCKET clientSocket = accept(listenSocket, (sockaddr*)&clientAddr, &clientLen);
            
            if (clientSocket != INVALID_SOCKET) {
                std::string peerAddr = inet_ntoa(clientAddr.sin_addr);
                int peerPort = ntohs(clientAddr.sin_port);
                
                std::cout << "[" << nodeId << "] Incoming connection from " << peerAddr << ":" << peerPort << std::endl;
                
                std::thread(&MeshNode::handleIncomingPeer, this, clientSocket, peerAddr).detach();
            }
        }
    }

    bool authenticatePeer(SOCKET socket, std::string& peerNodeId, int& peerListenPort) {
        // Wait for AUTH message
        char buffer[1024];
        memset(buffer, 0, sizeof(buffer));
        
        // Set timeout for authentication
        struct timeval tv;
        tv.tv_sec = 10;  // 10 second timeout
        tv.tv_usec = 0;
        setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        
        int bytesReceived = recv(socket, buffer, sizeof(buffer) - 1, 0);
        
        if (bytesReceived <= 0) {
            std::cout << "[" << nodeId << "] Authentication timeout or connection closed" << std::endl;
            return false;
        }
        
        std::string message(buffer, bytesReceived);
        
        // Expected format: AUTH:<password_hash>:<node_id>:<listen_port>
        if (message.find("AUTH:") == 0) {
            size_t pos1 = 5;  // After "AUTH:"
            size_t pos2 = message.find(':', pos1);
            size_t pos3 = message.find(':', pos2 + 1);
            
            if (pos2 == std::string::npos || pos3 == std::string::npos) {
                std::cout << "[" << nodeId << "] Invalid authentication format" << std::endl;
                return false;
            }
            
            std::string receivedHash = message.substr(pos1, pos2 - pos1);
            peerNodeId = message.substr(pos2 + 1, pos3 - pos2 - 1);
            peerListenPort = std::stoi(message.substr(pos3 + 1));
            
            if (receivedHash == passwordHash) {
                std::string response = "AUTH_OK:" + nodeId + ":" + std::to_string(listenPort);
                send(socket, response.c_str(), response.length(), 0);
                std::cout << "[" << nodeId << "] Peer " << peerNodeId << " authenticated successfully" << std::endl;
                return true;
            } else {
                std::string response = "AUTH_FAIL";
                send(socket, response.c_str(), response.length(), 0);
                std::cout << "[" << nodeId << "] Authentication failed - incorrect password" << std::endl;
                return false;
            }
        }
        
        std::cout << "[" << nodeId << "] Invalid authentication message" << std::endl;
        return false;
    }

    void handleIncomingPeer(SOCKET socket, const std::string& address) {
        std::string peerNodeId;
        int peerListenPort;
        
        // Authenticate the peer first
        if (!authenticatePeer(socket, peerNodeId, peerListenPort)) {
            closesocket(socket);
            return;
        }
        
        // Register the peer with their listen port for bidirectional communication
        {
            std::lock_guard<std::mutex> lock(peersMutex);
            std::string peerId = peerNodeId;
            
            // Check if we already have a connection to this peer
            if (peers.find(peerId) != peers.end() && peers[peerId].connected) {
                std::cout << "[" << nodeId << "] Already have a connection to " << peerNodeId << std::endl;
                closesocket(socket);
                return;
            }
            
            Peer peer;
            peer.nodeId = peerNodeId;
            peer.address = address;
            peer.port = 0;  // Unknown outgoing port
            peer.listenPort = peerListenPort;
            peer.socket = socket;
            peer.connected = true;
            peer.authenticated = true;
            peer.lastSeen = time(nullptr);
            peer.lastHeartbeat = time(nullptr);
            
            peers[peerId] = peer;
            std::cout << "[" << nodeId << "] Registered bidirectional peer: " << peerNodeId 
                      << " (listening on " << peerListenPort << ")" << std::endl;
        }
        
        // If authenticated, handle the connection normally
        handlePeerConnection(socket, address, peerNodeId, true);
    }

    void handlePeerConnection(SOCKET socket, const std::string& address, const std::string& peerNodeId, bool authenticated = false) {
        char buffer[1024];
        
        // Set socket timeout for non-blocking reads
        struct timeval tv;
        tv.tv_sec = 1;  // 1 second timeout
        tv.tv_usec = 0;
        setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        
        while (running) {
            memset(buffer, 0, sizeof(buffer));
            int bytesReceived = recv(socket, buffer, sizeof(buffer) - 1, 0);
            
            if (bytesReceived > 0) {
                std::string message(buffer, bytesReceived);
                
                // Update last seen time
                {
                    std::lock_guard<std::mutex> lock(peersMutex);
                    if (peers.find(peerNodeId) != peers.end()) {
                        peers[peerNodeId].lastSeen = time(nullptr);
                    }
                }
                
                // Process messages
                if (message.find("HEARTBEAT") == 0) {
                    // Update last heartbeat time
                    std::lock_guard<std::mutex> lock(peersMutex);
                    if (peers.find(peerNodeId) != peers.end()) {
                        peers[peerNodeId].lastHeartbeat = time(nullptr);
                    }
                } else if (message.find("DISCOVER") == 0) {
                    std::string response = "HELLO:" + nodeId;
                    send(socket, response.c_str(), response.length(), 0);
                } else {
                    // Regular message
                    std::cout << "[" << nodeId << "] Received from " << peerNodeId << ": " << message << std::endl;
                }
            } else if (bytesReceived == 0) {
                // Connection closed by peer
                std::cout << "[" << nodeId << "] Connection closed with " << peerNodeId << " (" << address << ")" << std::endl;
                
                // Mark peer as disconnected
                std::lock_guard<std::mutex> lock(peersMutex);
                if (peers.find(peerNodeId) != peers.end()) {
                    peers[peerNodeId].connected = false;
                }
                break;
            }
            // If bytesReceived < 0, it's a timeout, continue loop
        }
        
        closesocket(socket);
    }

    void heartbeatThread() {
        while (running) {
            std::this_thread::sleep_for(std::chrono::seconds(HEARTBEAT_INTERVAL));
            
            std::lock_guard<std::mutex> lock(peersMutex);
            time_t now = time(nullptr);
            
            for (auto& pair : peers) {
                if (pair.second.connected && pair.second.authenticated) {
                    // Send heartbeat
                    std::string heartbeat = "HEARTBEAT";
                    int result = send(pair.second.socket, heartbeat.c_str(), heartbeat.length(), 0);
                    
                    if (result == SOCKET_ERROR) {
                        std::cout << "[" << nodeId << "] Failed to send heartbeat to " << pair.second.nodeId << std::endl;
                        pair.second.connected = false;
                    }
                    
                    // Check if peer has timed out
                    if (now - pair.second.lastHeartbeat > HEARTBEAT_TIMEOUT) {
                        std::cout << "[" << nodeId << "] Peer " << pair.second.nodeId << " timed out" << std::endl;
                        pair.second.connected = false;
                        closesocket(pair.second.socket);
                    }
                }
            }
        }
    }

public:
    MeshNode(int port, const std::string& password) 
        : listenPort(port), running(false), listenSocket(INVALID_SOCKET) {
        initSockets();
        nodeId = generateNodeId();
        passwordHash = sha256(password);
        std::cout << "[" << nodeId << "] Password set (hash: " << passwordHash.substr(0, 16) << "...)" << std::endl;
    }

    ~MeshNode() {
        stop();
        cleanupSockets();
    }

    void start() {
        running = true;
        startListening();
        
        // Start accepting connections in a separate thread
        std::thread(&MeshNode::acceptConnections, this).detach();
        
        // Start heartbeat thread
        std::thread(&MeshNode::heartbeatThread, this).detach();
    }

    void stop() {
        running = false;
        
        if (listenSocket != INVALID_SOCKET) {
            closesocket(listenSocket);
        }
        
        std::lock_guard<std::mutex> lock(peersMutex);
        for (auto& pair : peers) {
            if (pair.second.connected && pair.second.socket != INVALID_SOCKET) {
                closesocket(pair.second.socket);
            }
        }
    }

    bool connectToPeer(const std::string& address, int port, const std::string& password) {
        SOCKET peerSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (peerSocket == INVALID_SOCKET) {
            std::cerr << "Failed to create socket for peer connection" << std::endl;
            return false;
        }

        sockaddr_in peerAddr;
        peerAddr.sin_family = AF_INET;
        peerAddr.sin_port = htons(port);
        
#ifdef _WIN32
        peerAddr.sin_addr.s_addr = inet_addr(address.c_str());
#else
        inet_pton(AF_INET, address.c_str(), &peerAddr.sin_addr);
#endif

        std::cout << "[" << nodeId << "] Connecting to " << address << ":" << port << "..." << std::endl;
        
        if (connect(peerSocket, (sockaddr*)&peerAddr, sizeof(peerAddr)) == SOCKET_ERROR) {
            std::cerr << "Failed to connect to peer" << std::endl;
            closesocket(peerSocket);
            return false;
        }

        std::cout << "[" << nodeId << "] Connected! Authenticating..." << std::endl;

        // Send authentication with our node info
        std::string authMsg = "AUTH:" + sha256(password) + ":" + nodeId + ":" + std::to_string(listenPort);
        send(peerSocket, authMsg.c_str(), authMsg.length(), 0);

        // Wait for response
        char buffer[1024];
        memset(buffer, 0, sizeof(buffer));
        
        struct timeval tv;
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        setsockopt(peerSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        
        int bytesReceived = recv(peerSocket, buffer, sizeof(buffer) - 1, 0);
        
        if (bytesReceived <= 0) {
            std::cerr << "Authentication timeout" << std::endl;
            closesocket(peerSocket);
            return false;
        }
        
        std::string response(buffer, bytesReceived);
        
        // Expected format: AUTH_OK:<peer_node_id>:<peer_listen_port>
        if (response.find("AUTH_OK") == 0) {
            size_t pos1 = 8;  // After "AUTH_OK:"
            size_t pos2 = response.find(':', pos1);
            
            std::string peerNodeId;
            int peerListenPort = port;  // Default to connection port
            
            if (pos2 != std::string::npos) {
                peerNodeId = response.substr(pos1, pos2 - pos1);
                peerListenPort = std::stoi(response.substr(pos2 + 1));
            } else {
                peerNodeId = response.substr(pos1);
            }
            
            std::cout << "[" << nodeId << "] Authentication successful with " << peerNodeId << "!" << std::endl;
            
            {
                std::lock_guard<std::mutex> lock(peersMutex);
                
                // Check if we already have a connection to this peer
                if (peers.find(peerNodeId) != peers.end() && peers[peerNodeId].connected) {
                    std::cout << "[" << nodeId << "] Already have a connection to " << peerNodeId << std::endl;
                    closesocket(peerSocket);
                    return false;
                }
                
                Peer peer;
                peer.nodeId = peerNodeId;
                peer.address = address;
                peer.port = port;
                peer.listenPort = peerListenPort;
                peer.socket = peerSocket;
                peer.connected = true;
                peer.authenticated = true;
                peer.lastSeen = time(nullptr);
                peer.lastHeartbeat = time(nullptr);
                
                peers[peerNodeId] = peer;
                std::cout << "[" << nodeId << "] Registered bidirectional peer: " << peerNodeId 
                          << " (listening on " << peerListenPort << ")" << std::endl;
            }

            // Start handling this peer in a separate thread
            std::thread(&MeshNode::handlePeerConnection, this, peerSocket, address, peerNodeId, true).detach();

            // Send discovery message
            std::string discoverMsg = "DISCOVER:" + nodeId;
            send(peerSocket, discoverMsg.c_str(), discoverMsg.length(), 0);

            return true;
        } else {
            std::cerr << "[" << nodeId << "] Authentication failed - incorrect password" << std::endl;
            closesocket(peerSocket);
            return false;
        }
    }

    void broadcastMessage(const std::string& message) {
        std::lock_guard<std::mutex> lock(peersMutex);
        
        std::cout << "[" << nodeId << "] Broadcasting: " << message << std::endl;
        
        for (auto& pair : peers) {
            if (pair.second.connected && pair.second.authenticated && pair.second.socket != INVALID_SOCKET) {
                send(pair.second.socket, message.c_str(), message.length(), 0);
            }
        }
    }

    void listPeers() {
        std::lock_guard<std::mutex> lock(peersMutex);
        
        std::cout << "\n=== Connected Peers ===" << std::endl;
        if (peers.empty()) {
            std::cout << "No peers connected" << std::endl;
        } else {
            for (const auto& pair : peers) {
                if (pair.second.connected && pair.second.authenticated) {
                    std::cout << "  - " << pair.second.nodeId 
                              << " (" << pair.second.address << ":" << pair.second.listenPort << ")"
                              << " [Bidirectional]" << std::endl;
                }
            }
        }
        std::cout << "======================\n" << std::endl;
    }

    std::string getNodeId() const {
        return nodeId;
    }
};

int main(int argc, char* argv[]) {
    int port = 8888;
    std::string password;
    
    if (argc > 1) {
        port = std::atoi(argv[1]);
    }

    std::cout << "=== Mesh Network Node (With Password Authentication) ===" << std::endl;
    std::cout << "Starting on port " << port << std::endl;
    
    // Get password
    std::cout << "\nEnter network password: ";
    std::getline(std::cin, password);
    
    if (password.empty()) {
        std::cerr << "Password cannot be empty!" << std::endl;
        return 1;
    }

    try {
        MeshNode node(port, password);
        node.start();

        std::cout << "\nNode ID: " << node.getNodeId() << std::endl;
        std::cout << "\nCommands:" << std::endl;
        std::cout << "  connect <ip> <port> - Connect to a peer (will prompt for password)" << std::endl;
        std::cout << "  send <message>      - Broadcast message to all peers" << std::endl;
        std::cout << "  list                - List connected peers" << std::endl;
        std::cout << "  quit                - Exit program\n" << std::endl;

        std::string command;
        while (true) {
            std::cout << "> ";
            std::getline(std::cin, command);

            if (command == "quit" || command == "exit") {
                break;
            } else if (command.find("connect ") == 0) {
                size_t space1 = command.find(' ', 8);
                if (space1 != std::string::npos) {
                    std::string ip = command.substr(8, space1 - 8);
                    int peerPort = std::stoi(command.substr(space1 + 1));
                    
                    std::cout << "Enter password for peer: ";
                    std::string peerPassword;
                    std::getline(std::cin, peerPassword);
                    
                    node.connectToPeer(ip, peerPort, peerPassword);
                } else {
                    std::cout << "Usage: connect <ip> <port>" << std::endl;
                }
            } else if (command.find("send ") == 0) {
                std::string message = command.substr(5);
                node.broadcastMessage(message);
            } else if (command == "list") {
                node.listPeers();
            } else if (!command.empty()) {
                std::cout << "Unknown command. Try: connect, send, list, quit" << std::endl;
            }
        }

        std::cout << "Shutting down..." << std::endl;
        node.stop();

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}