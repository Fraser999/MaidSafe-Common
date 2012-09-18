/*******************************************************************************
 *  Copyright 2012 maidsafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of maidsafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the licence   *
 *  file licence.txt found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of maidsafe.net. *
 ******************************************************************************/

#ifndef MAIDSAFE_COMMON_NODE_ID_H_
#define MAIDSAFE_COMMON_NODE_ID_H_

#include <cstdint>
#include <string>
#include <vector>
#include "maidsafe/common/error.h"

namespace maidsafe {

extern const uint16_t kKeySizeBytes;
extern const uint16_t kKeySizeBits;
extern const std::string kZeroId;

size_t BitToByteCount(const size_t& bit_count);

class NodeId {
 public:
  enum IdType { kMaxId, kRandomId };
  enum EncodingType { kBinary, kHex, kBase32, kBase64 };

  // Creates an ID equal to 0.
  NodeId();

  NodeId(const NodeId& other);

  // Creates an ID = (2 ^ kKeySizeBits) - 1 or a random ID in the  interval [0, 2 ^ kKeySizeBits).
  explicit NodeId(const IdType& type);

  // Creates a NodeId from a raw (decoded) string.
  explicit NodeId(const std::string& id);
  explicit NodeId(const std::string& id, std::error_code &error);

  // Creates a NodeId from an encoded string.
  NodeId(const std::string& id, const EncodingType& encoding_type);

  // Creates a NodeId equal to 2 ^ power.
  explicit NodeId(const uint16_t& power);

  // Creates a random NodeId in range [lower ID, higher ID].  Prefer to pass lower ID as id1.
  NodeId(const NodeId& id1, const NodeId& id2);

  // Checks if id1 is closer in XOR distance to target_id than id2.
  static bool CloserToTarget(const NodeId& id1, const NodeId& id2, const NodeId& target_id);

  // Decoded representation of the ID.
  const std::string String() const;

  // Encoded representation of the ID.
  const std::string ToStringEncoded(const EncodingType& encoding_type) const;

  // Checks that raw_id_ has size kKeySizeBytes.
  bool IsValid() const;

  bool Empty() const;

  bool operator()(const NodeId& lhs, const NodeId& rhs) const;
  bool operator==(const NodeId& rhs) const;
  bool operator!=(const NodeId& rhs) const;
  bool operator<(const NodeId& rhs) const;
  bool operator>(const NodeId& rhs) const;
  bool operator<=(const NodeId& rhs) const;
  bool operator>=(const NodeId& rhs) const;
  NodeId& operator=(const NodeId& rhs);

  // XOR distance between two IDs.  XOR bit to bit.
  const NodeId operator^(const NodeId& rhs) const;

 private:
  std::string EncodeToBinary() const;
  void DecodeFromBinary(const std::string& binary_id);
  std::string raw_id_;
};

// Returns an abbreviated hex representation of node_id.
std::string DebugId(const NodeId& node_id);

}  // namespace maidsafe

#endif  // MAIDSAFE_COMMON_NODE_ID_H_
