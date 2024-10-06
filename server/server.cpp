#include <iostream>
#include <fstream>
#include <thread>
#include <vector>
#include <mutex>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

using namespace std;

mutex log_mutex;

class Server {
public:
    Server(int port) : serverPort(port) {}

    void run() {
        int server_fd, new_socket;
        struct sockaddr_in address;
        int opt = 1;
        int size = sizeof(address);

        if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
            cerr << "Socket failed\n";
            exit(EXIT_FAILURE);
        }

        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(serverPort);

        if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
            cerr << "Bind failed\n";
            exit(EXIT_FAILURE);
        }

        if (listen(server_fd, 3) < 0) {
            cerr << "Listen failed\n";
            exit(EXIT_FAILURE);
        }

        while (true) {
            if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&size)) < 0) {
                cerr << "Accept failed\n";
                exit(EXIT_FAILURE);
            }
            thread(&Server::handleClient, this, new_socket).detach();
        }
    }

private:
    int serverPort;
    string decryptRSA(const string& encryptedData, RSA* rsa) {
        vector<unsigned char> decrypted(RSA_size(rsa));
        int result = RSA_private_decrypt(encryptedData.size(), (const unsigned char*)encryptedData.c_str(), decrypted.data(), rsa, RSA_PKCS1_OAEP_PADDING);
        if (result == -1) {
            char err[130];
            ERR_load_crypto_strings();
            ERR_error_string(ERR_get_error(), err);
            cerr << "Error decrypting message: " << err << endl;
            return "";
        }
        return string(decrypted.begin(), decrypted.begin() + result);
    }
    RSA* loadPrivateKey(const string& privateKeyPath) {
        FILE* privateFile = fopen(privateKeyPath.c_str(), "rb");
        if (!privateFile) {
            cerr << "Could not open private key file\n";
            return nullptr;
        }
        RSA* rsa = PEM_read_RSAPrivateKey(privateFile, nullptr, nullptr, nullptr);
        fclose(privateFile);
        return rsa;
    }

    void handleClient(int socket) {
        RSA* rsa = loadPrivateKey("private.pem");
        if (!rsa) {
            cerr << "Failed to load private key.\n";
            close(socket);
            return;
        }

        char buffer[1024] = {0};
        int valread = read(socket, buffer, sizeof(buffer));

        if (valread <= 0) {
            cerr << "Error reading from socket.\n";
            close(socket);
            return;
        }
        string encryptedMessage(buffer, valread);
        string decryptedMessage = decryptRSA(encryptedMessage, rsa);

        if (!decryptedMessage.empty()) {
            cout << "Decrypted message: " << decryptedMessage << endl;
            lock_guard<mutex> guard(log_mutex);
            ofstream log_file("log.txt", ios_base::app);
            log_file << decryptedMessage << endl;
        }

        RSA_free(rsa);
        close(socket);
    }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cerr << "Usage: <port>\n";
        exit(1);
    }

    int sPort = stoi(argv[1]);
    Server server(sPort);
    server.run();

    return 0;
}
