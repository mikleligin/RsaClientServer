#include <iostream>
#include <string>
#include <chrono>
#include <ctime>
#include <thread>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <vector>
using namespace std;
class Client{
    public:
        Client(const string& name, int port, int period):
        clientName(name), serverPort(port), timePeriod(period){};
        void run(){
            while(true){
                connectClient();
                std::this_thread::sleep_for(std::chrono::seconds(timePeriod));
            }
        }
    private:
        string clientName;
        int serverPort = 0;
        int timePeriod = 0;

        RSA* loadPublicKey(const std::string& publicKeyPath) {
            FILE* publicFile = fopen(publicKeyPath.c_str(), "rb");
            if (!publicFile) {
                std::cerr << "Could not open public key file." << std::endl;
                return nullptr;
            }

            RSA* rsa = PEM_read_RSA_PUBKEY(publicFile, nullptr, nullptr, nullptr);
            fclose(publicFile);
            return rsa;
        }
        std::string encryptRSA(const std::string& data, RSA* rsa) {
            std::vector<unsigned char> encrypted(RSA_size(rsa));
            int result = RSA_public_encrypt(data.size(),(const unsigned char*)data.c_str(),encrypted.data(), rsa, RSA_PKCS1_OAEP_PADDING);

            if (result == -1) {
                char err[130];
                ERR_load_crypto_strings();
                ERR_error_string(ERR_get_error(), err);
                std::cerr << "Error encrypting message: " << err << std::endl;
                return "";
            }
            
            return std::string(encrypted.begin(), encrypted.end());
        }
        void connectClient()
        {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in servAddr;
            servAddr.sin_family = AF_INET;
            servAddr.sin_port = htons(serverPort);
            if(inet_pton(AF_INET, "127.0.0.1",&servAddr.sin_addr)<=0){
                cerr<<"Invalid address\n";
                close(sock);
                return;
            }
            if(connect(sock, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0){
                cerr<<"No Connection :(\n";
                close(sock);
                return;
            }
            RSA* rsa = loadPublicKey("public.pem");
            if (!rsa) {
                std::cerr << "Failed to load public key." << std::endl;
                return;
            }
            auto now = chrono::system_clock::now();
            auto ms = chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
            time_t t = chrono::system_clock::to_time_t(now);
            tm tm = *std::localtime(&t);
            string message = "Hello World!";
            std::string encryptedMessage = encryptRSA(message, rsa);
            send(sock, encryptedMessage.c_str(), encryptedMessage.size(),0);
            close(sock);
        }
};

int main(int argc, char* argv[])
{
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <client_name> <server_port> <period>\n";
        return 1;
    }
    
    string name = argv[1];
    int port = stoi(argv[2]);
    int period = stoi(argv[3]);
    Client client(name, port, period);
    client.run();
    return 0;
}