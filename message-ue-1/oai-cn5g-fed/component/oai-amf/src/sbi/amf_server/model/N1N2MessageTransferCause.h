/**
 * Namf_Communication
 * AMF Communication Service © 2019, 3GPP Organizational Partners (ARIB, ATIS,
 * CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.1.0.alpha-1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */
/*
 * N1N2MessageTransferCause.h
 *
 *
 */

#ifndef N1N2MessageTransferCause_H_
#define N1N2MessageTransferCause_H_

#include <nlohmann/json.hpp>

namespace oai {
namespace amf {
namespace model {

/// <summary>
///
/// </summary>
class N1N2MessageTransferCause {
 public:
  N1N2MessageTransferCause();
  virtual ~N1N2MessageTransferCause();

  void validate();

  /////////////////////////////////////////////
  /// N1N2MessageTransferCause members

  friend void to_json(nlohmann::json& j, const N1N2MessageTransferCause& o);
  friend void from_json(const nlohmann::json& j, N1N2MessageTransferCause& o);

 protected:
};

}  // namespace model
}  // namespace amf
}  // namespace oai

#endif /* N1N2MessageTransferCause_H_ */
