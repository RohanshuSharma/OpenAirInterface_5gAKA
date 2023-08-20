/**
 * NRF NFManagement Service
 * NRF NFManagement Service. © 2019, 3GPP Organizational Partners (ARIB, ATIS,
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
 * Ipv6Prefix.h
 *
 *
 */

#ifndef Ipv6Prefix_H_
#define Ipv6Prefix_H_

#include <nlohmann/json.hpp>

namespace oai {
namespace nssf_server {
namespace model {

/// <summary>
///
/// </summary>
class Ipv6Prefix {
 public:
  Ipv6Prefix();
  virtual ~Ipv6Prefix();

  void validate();

  /////////////////////////////////////////////
  /// Ipv6Prefix members

  friend void to_json(nlohmann::json& j, const Ipv6Prefix& o);
  friend void from_json(const nlohmann::json& j, Ipv6Prefix& o);

 protected:
};

}  // namespace model
}  // namespace nssf_server
}  // namespace oai

#endif /* Ipv6Prefix_H_ */