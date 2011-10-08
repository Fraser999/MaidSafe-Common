// /* Copyright (c) 2011 maidsafe.net limited
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice,
//     this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution.
//     * Neither the name of the maidsafe.net limited nor the names of its
//     contributors may be used to endorse or promote products derived from this
//     software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
// TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// */
// 
// #include "maidsafe/common/securifier.h"
// #include <algorithm>
// #include "maidsafe/common/rsa.h"
// #include "maidsafe/common/crypto.h"
// 
// namespace maidsafe {
// 
//   Securifier::Securifier(std::shared_ptr<AsymmetricCrypto> Asymm,
//                          const AsymmKeys &sign_keys,
//                          const AsymmKeys &decrypt_keys)
//   : sign_keys_(sign_keys),
//     decrypt_keys_(decrypt_keys),
//     parameters_() {}
// 
//     Securifier::Securifier(std::shared_ptr<AsymmetricCrypto> Asymm,
//                            const AsymmKeys &keys)
//     : sign_keys_(keys),
//       decrypt_keys_(keys),
//       parameters_() {}
// 
// Securifier::~Securifier() {}
// 
// void Securifier::AddParameters(const std::vector<std::string> &parameters) {
//   size_t original_size(parameters_.size());
//   parameters_.resize(original_size + parameters.size());
//   std::copy(parameters.begin(), parameters.end(),
//             parameters_.begin() + original_size);
// }
// 
// void Securifier::ClearParameters() {
//   parameters_.clear();
// }
// 
// std::vector<std::string> Securifier::parameters() const {
//   return parameters_;
// }
// 
// int Securifier::Sign(const std::string &value, std::string *result) const {
//   return Asymm_->Sign(value, result, sign_keys_.priv_key);
// }
// 
// std::string Securifier::SignWithParameters(const std::string &value) const {
//   std::string concatenation(value);
//   for (auto it = parameters_.begin(); it != parameters_.end(); ++it)
//     concatenation += *it;
//   return crypto::AsymSign(concatenation, kSigningPrivateKey_);
// }
// 
// std::string Securifier::AsymmetricEncrypt(
//     const std::string &value,
//     const std::string &recipient_public_key) const {
//   return crypto::AsymEncrypt(value, recipient_public_key);
// }
// 
// void Securifier::GetPublicKeyAndValidation(const std::string &/*public_key_id*/,
//                                            std::string *public_key,
//                                            std::string *public_key_validation) {
//   if (public_key)
//     public_key->clear();
//   if (public_key_validation)
//     public_key_validation->clear();
// }
// 
// void Securifier::GetPublicKeyAndValidation(
//     const std::string &/*public_key_id*/,
//     GetPublicKeyAndValidationCallback callback) {
//   callback("", "");
// }
// 
// bool Securifier::Validate(const std::string &value,
//                           const std::string &value_signature,
//                           const std::string &/*public_key_id*/,
//                           const std::string &public_key,
//                           const std::string &/*public_key_validation*/,
//                           const std::string &/*kademlia_key*/) const {
//   if (!public_key.empty())
//     return crypto::AsymCheckSig(value, value_signature, public_key);
//   else
//     return true;
// }
// 
// bool Securifier::ValidateWithParameters(
//     const std::string &value,
//     const std::string &value_signature,
//     const std::string &/*public_key_id*/,
//     const std::string &public_key,
//     const std::string &/*public_key_validation*/,
//     const std::string &/*kademlia_key*/) const {
//   if (!public_key.empty()) {
//     std::string concatenation(value);
//     for (auto it = parameters_.begin(); it != parameters_.end(); ++it)
//       concatenation += *it;
//     return crypto::AsymCheckSig(concatenation, value_signature, public_key);
//   } else {
//     return true;
//   }
// }
// 
// std::string Securifier::AsymmetricDecrypt(
//     const std::string &encrypted_value) const {
//   return crypto::AsymDecrypt(encrypted_value, kAsymmetricDecryptionPrivateKey_);
// }
// 
// std::string Securifier::kSigningKeys() const {
//   return kSigningKeyId_;
// }
// 
// std::string Securifier::kAsymmetricDecryptionKeys() const {
//   return kAsymmetricDecryptionKeyId_;
// }
// 
// 
// 
// }  // namespace maidsafe
