#include <iostream>
#include "sha.h"
#include "md5.h"
#include "filters.h"
#include "base64.h"
#include "hex.h"
#include "aes.h"
#include "modes.h"
#include "des.h"
#include "rsa.h"
#include "osrng.h"
#include "nbtheory.h"
#include "integer.h"
#include "cryptlib.h"



#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

//MD5   SHA256    AES   DES DSM RSA


using namespace std;


void MD5(std::string message)
{
    CryptoPP::MD5 hash;
    CryptoPP::byte digest[ CryptoPP::MD5::DIGESTSIZE ];

    hash.CalculateDigest( digest, (CryptoPP::byte*) message.c_str(), message.length() );

    CryptoPP::HexEncoder encoder;
    std::string output;
    encoder.Attach( new CryptoPP::StringSink( output ) );
    encoder.Put( digest, sizeof(digest) );
    encoder.MessageEnd();

    cout << "Text: " << message << endl << endl;
    cout << "MD5: " << output << endl;

}

void SHA256(string message)
{
    CryptoPP::SHA256 hash;
    CryptoPP::byte digest[ CryptoPP::SHA256::DIGESTSIZE ];

    hash.CalculateDigest( digest, (CryptoPP::byte*) message.c_str(), message.length() );

    CryptoPP::HexEncoder encoder;
    std::string output;
    encoder.Attach( new CryptoPP::StringSink( output ) );
    encoder.Put( digest, sizeof(digest) );
    encoder.MessageEnd();

    cout << "Text: " << message << endl << endl;
    cout << "SHA256: " << output << endl;

}

void AES(string message)
{
    //Key and IV setup
    //AES encryption uses a secret key of a variable length (128-bit, 196-bit or 256-
    //bit). This key is secretly exchanged between two parties before communication
    //begins. DEFAULT_KEYLENGTH= 16 bytes
    CryptoPP::byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ], iv[ CryptoPP::AES::BLOCKSIZE ];
    memset( key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );
    memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );

    //
    // String and Sink setup
    //
    std::string ciphertext;
    std::string decryptedtext;

    //
    // Print Plain Text
    //
    std::cout << "Text to encrypt: " << message << std::endl << std::endl;

    //
    // Create Cipher Text
    //
    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv );

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( ciphertext ) );
    stfEncryptor.Put( reinterpret_cast<const unsigned char*>( message.c_str() ), message.length());
    stfEncryptor.MessageEnd();

    //
    // Print Cipher Text
    //
    std::cout << "Encrypted Text: " ;


    for( int i = 0; i < ciphertext.size(); i++ ) {

        std::cout << std::hex << (0xFF & static_cast<CryptoPP::byte>(ciphertext[i]));
    }

    std::cout << std::endl << std::endl;

    //
    // Decrypt
    //
    CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv );

    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( decryptedtext ) );
    stfDecryptor.Put( reinterpret_cast<const unsigned char*>( ciphertext.c_str() ), ciphertext.size());
    stfDecryptor.MessageEnd();

    //
    // Print Decrypted Text
    //
    std::cout << "Decrypted Text: " << decryptedtext << std::endl;
}

void DES(CryptoPP::byte *block, size_t length, CryptoPP::CipherDir direction)
{
    const char *keyString = "bardzo dobry klucz";

    CryptoPP::byte key[CryptoPP::DES_EDE2::KEYLENGTH];
    memcpy(key, keyString, CryptoPP::DES_EDE2::KEYLENGTH);
    CryptoPP::BlockTransformation *t = NULL;

    if(direction == CryptoPP::ENCRYPTION)
        t = new CryptoPP::DES_EDE2_Encryption(key, CryptoPP::DES_EDE2::KEYLENGTH);
    else
        t = new CryptoPP::DES_EDE2_Decryption(key, CryptoPP::DES_EDE2::KEYLENGTH);

    int steps = length / t->BlockSize();
    for(int i=0; i<steps; i++){
        int offset = i * t->BlockSize();
        t->ProcessBlock(block + offset);
    }

    delete t;
}

void RSA(string message)
{
// Bob artificially small key pair
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::RSA::PrivateKey privKey;

    privKey.GenerateRandomWithKeySize(prng, 1024);
    CryptoPP::RSA::PublicKey pubKey(privKey);

    CryptoPP::SecByteBlock buff1, buff2, buff3;

    // Convenience
    const CryptoPP::Integer& n = pubKey.GetModulus();
    const CryptoPP::Integer& e = pubKey.GetPublicExponent();
    //const CryptoPP::Integer& d = privKey.GetPrivateExponent();


    cout << "RSA public Key: (" << std::hex << e << ", " << std::hex << n << ")\n\n";

    //cout << "RSA private Key: (" << std::hex << d << ", " << std::hex << n << ")\n\n";

    // Alice original message to be signed by Bob
    CryptoPP::SecByteBlock orig((const CryptoPP::byte*) "Testowy t", 8);
    CryptoPP::Integer m(orig.data(), orig.size());
    cout << "Text to encrypt: " << message << endl;

    CryptoPP::Integer r;
    do {
        r.Randomize(prng, CryptoPP::Integer::One(), n - CryptoPP::Integer::One());
    } while (!RelativelyPrime(r, n));

    // Blinding factor
    CryptoPP::Integer b = a_exp_b_mod_c(r, e, n);

    // blinding message
    CryptoPP::Integer mm = a_times_b_mod_c(m, b, n);
    cout << "Encrypted Text: " << std::hex << mm << endl;

    // signing
    CryptoPP::Integer ss = privKey.CalculateInverse(prng, mm);

    // Alice checks s(s'(x)) = x. This is from Chaum's paper
    CryptoPP::Integer c = pubKey.ApplyFunction(ss);
    if (c != mm)
        throw runtime_error("Alice cross-check failed");

    CryptoPP::Integer s = a_times_b_mod_c(ss, r.InverseMod(n), n);

    CryptoPP::Integer v = pubKey.ApplyFunction(s);

    size_t len = v.MinEncodedSize();
    string str;

    str.resize(len);
    v.Encode((CryptoPP::byte *)str.data(), str.size(), CryptoPP::Integer::UNSIGNED);

    cout << "Decrypted Text: " << str << endl;

}

int main() {
    cout << "Hash - MD5\n\n";

    MD5("Testowy tekst");

    cout << "\n---------------------\n";
    cout << "Hash - SHA256\n\n";

    SHA256("Testowy tekst");

    cout << "\n---------------------\n";
    cout << "AES Method\n\n";

    AES("Testowy tekst");

    cout << "\n---------------------\n";
    cout << "DES Method\n\n";

    CryptoPP::byte block[1024] = "Testowy tekst";

    printf("Text to encrypt: %s\n\n", block);

    DES(block, 16, CryptoPP::ENCRYPTION);

    printf("Encrypted Text: %s\n\n", block);

    DES(block, 16, CryptoPP::DECRYPTION);

    printf("Decrypted Text: %s\n\n", block);

    cout << "\n---------------------\n";
    cout << "RSA Method\n\n";

    RSA("Testowy tekst");
    return 0;
}

