/*
 *  Copyright (c) 2018-2019, SLikeSoft UG (haftungsbeschränkt)
 *
 *  This source code is  licensed under the MIT-style license found in the license.txt
 *  file in the root directory of this source tree.
 */
#include "slikenet/crypto/fileencrypter.h"

#include <openssl/pem.h> // used for PEM_read_bio_RSAPrivateKey, PEM_read_bio_RSA_PUBKEY, EVP_xxx, BIO_xxx
#include <openssl/err.h> // used for ERR_xxxx

namespace SLNet
{
	namespace Experimental
	{
		namespace Crypto
		{
			CFileEncrypter::CFileEncrypter(const CSecureString&, const char *publicKey, size_t publicKeyLength) :
				m_privateKey(nullptr),
				m_publicKey(nullptr)
			{
				// #high - error / exception handling
				(void)SetPublicKey(publicKey, publicKeyLength);
			}

			CFileEncrypter::~CFileEncrypter()
			{
				if (m_publicKey != nullptr) {
					// #high - free the BIO too
					RSA_free(m_publicKey);
				}
			}

			const unsigned char* CFileEncrypter::SignData(const unsigned char *data, const size_t dataLength)
			{
				return nullptr;
			}

			const char* CFileEncrypter::SignDataBase64(const unsigned char *data, const size_t dataLength)
			{
				return nullptr;
			}

			bool CFileEncrypter::VerifyData(const unsigned char *data, const size_t dataLength, const unsigned char *signature, const size_t signatureLength)
			{
				return false;
			}

			bool CFileEncrypter::VerifyDataBase64(const unsigned char *data, const size_t dataLength, const char *signature, const size_t signatureLength)
			{
					return false;
			}

			const char* CFileEncrypter::SetPublicKey(const char* publicKey, size_t publicKeyLength)
			{
				if (m_publicKey != nullptr) {
					// #high - free the BIO too
					RSA_free(m_publicKey);
				}

				// #med - review interface handling (const cast...)
				// #high - size_t -> int cast...
				BIO *const keyBIO = BIO_new_mem_buf(const_cast<char*>(publicKey), static_cast<int>(publicKeyLength));
				// #high - error/exception handling
				// #high - review &m_publicKey
				m_publicKey = PEM_read_bio_RSA_PUBKEY(keyBIO, &m_publicKey, nullptr, nullptr);
				if (m_publicKey == nullptr) {
					// #high - move to OpenSSLHelper::Init()
					ERR_load_crypto_strings();
					return ERR_error_string(ERR_get_error(), nullptr);
				}

				return "";
			}
		}
	}
}