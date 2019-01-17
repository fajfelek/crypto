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

void DSM()
{
    using namespace CryptoPP;
    // Bob artificially small key pair
    AutoSeededRandomPool prng;
    RSA::PrivateKey privKey;

    privKey.GenerateRandomWithKeySize(prng, 64);
    RSA::PublicKey pubKey(privKey);

    // Convenience
    const Integer& n = pubKey.GetModulus();
    const Integer& e = pubKey.GetPublicExponent();
    const Integer& d = privKey.GetPrivateExponent();

    // Print params
    cout << "Pub mod: " << std::hex << pubKey.GetModulus() << endl;
    cout << "Pub exp: " << std::hex << e << endl;
    cout << "Priv mod: " << std::hex << privKey.GetModulus() << endl;
    cout << "Priv exp: " << std::hex << d << endl;

    // For sizing the hashed message buffer. This should be SHA256 size.
    const size_t SIG_SIZE = UnsignedMin(SHA256::BLOCKSIZE, n.ByteCount());

    // Scratch
    SecByteBlock buff1, buff2, buff3;

    // Alice original message to be signed by Bob
    SecByteBlock orig((const CryptoPP::byte*)"secret", 6);
    Integer m(orig.data(), orig.size());
    cout << "Message: " << std::hex << m << endl;

    // Hash message per Rabin (1979)
    buff1.resize(SIG_SIZE);
    CryptoPP::SHA256 hash1;
    hash1.CalculateTruncatedDigest(buff1, buff1.size(), orig, orig.size());

    // H(m) as Integer
    Integer hm(buff1.data(), buff1.size());
    cout << "H(m): " << std::hex << hm << endl;

    // Alice blinding
    Integer r;
    do {
        r.Randomize(prng, Integer::One(), n - Integer::One());
    } while (!RelativelyPrime(r, n));

    // Blinding factor
    Integer b = a_exp_b_mod_c(r, e, n);
    cout << "Random: " << std::hex << b << endl;

    // Alice blinded message
    Integer mm = a_times_b_mod_c(hm, b, n);
    cout << "Blind msg: " << std::hex << mm << endl;

    // Bob sign
    Integer ss = privKey.CalculateInverse(prng, mm);
    cout << "Blind sign: " << ss << endl;

    // Alice checks s(s'(x)) = x. This is from Chaum's paper
    Integer c = pubKey.ApplyFunction(ss);
    cout << "Check sign: " << c << endl;
    if (c != mm)
        throw runtime_error("Alice cross-check failed");

    // Alice remove blinding
    Integer s = a_times_b_mod_c(ss, r.InverseMod(n), n);
    cout << "Unblind sign: " << s << endl;

    // Eve verifies
    Integer v = pubKey.ApplyFunction(s);
    cout << "Verify: " << std::hex << v << endl;

    // Convert to a string
    size_t req = v.MinEncodedSize();
    buff2.resize(req);
    v.Encode(&buff2[0], buff2.size());

    // Hash message per Rabin (1979)
    buff3.resize(SIG_SIZE);
    CryptoPP::SHA256 hash2;
    hash2.CalculateTruncatedDigest(buff3, buff3.size(), orig, orig.size());

    // Constant time compare
    bool equal = buff2.size() == buff3.size() && VerifyBufsEqual(
            buff2.data(), buff3.data(), buff3.size());

    if (!equal)
        throw runtime_error("Eve verified failed");

    cout << "Verified signature" << endl;

}


void RSA(string message)
{
    using namespace CryptoPP;

    ///////////////////////////////////////
// Pseudo Random Number Generator
    AutoSeededRandomPool rng;

///////////////////////////////////////
// Generate Parameters
    InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 1024);

///////////////////////////////////////
// Generated Parameters
    const Integer& n = params.GetModulus();
    const Integer& p = params.GetPrime1();
    const Integer& q = params.GetPrime2();
    const Integer& d = params.GetPrivateExponent();
    const Integer& e = params.GetPublicExponent();

///////////////////////////////////////
// Dump
    cout << "RSA Parameters:" << endl;
    cout << " n: " << n << endl;
    cout << " p: " << p << endl;
    cout << " q: " << q << endl;
    cout << " d: " << d << endl;
    cout << " e: " << e << endl;

///////////////////////////////////////
// Create Keys
    RSA::PrivateKey privateKey(params);
    RSA::PublicKey publicKey(params);

    string cipher, recovered;

////////////////////////////////////////////////
// Encryption
    RSAES_OAEP_SHA_Encryptor enc(publicKey);

    StringSource ss1(message, true,
                     new PK_EncryptorFilter(rng, enc,
                                            new StringSink(cipher)
                     ) // PK_EncryptorFilter
    ); // StringSource

    cout << "\nText to encrypt: " << message << endl;

    cout << "\nEncrypted Text: " << cipher << endl;

////////////////////////////////////////////////
// Decryption
    RSAES_OAEP_SHA_Decryptor dec(privateKey);

    StringSource ss2(cipher, true,
                     new PK_DecryptorFilter(rng, dec,
                                            new StringSink(recovered)
                     ) // PK_DecryptorFilter
    ); // StringSource

    cout << "\nDecrypted Text: " << recovered << endl;

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

    cout << "\n---------------------\n";
    cout << "Digital Signature Method\n\n";

    DSM();

    return 0;
}

