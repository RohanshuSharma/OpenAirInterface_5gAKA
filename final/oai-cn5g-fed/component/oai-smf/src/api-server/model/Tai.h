/**
 * Nsmf_PDUSession
 * SMF PDU Session Service. © 2019, 3GPP Organizational Partners (ARIB, ATIS,
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
 * Tai.h
 *
 *
 */

#ifndef Tai_H_
#define Tai_H_

#include <string>
#include "PlmnId.h"
#include <nlohmann/json.hpp>

namespace oai {
namespace smf_server {
namespace model {

/// <summary>
///
/// </summary>
class Tai {
 public:
  Tai();
  virtual ~Tai();

  void validate();

  bool validate(std::stringstream& msg) const;

  bool validate(std::stringstream& msg, const std::string& pathPrefix) const;

  bool operator==(const Tai& rhs) const;
  bool operator!=(const Tai& rhs) const;

  /////////////////////////////////////////////
  /// Tai members

  /// <summary>
  ///
  /// </summary>
  PlmnId getPlmnId() const;
  void setPlmnId(PlmnId const& value);
  /// <summary>
  ///
  /// </summary>
  std::string getTac() const;
  void setTac(std::string const& value);

  friend void to_json(nlohmann::json& j, const Tai& o);
  friend void from_json(const nlohmann::json& j, Tai& o);

 protected:
  PlmnId m_PlmnId;

  std::string m_Tac;
};

}  // namespace model
}  // namespace smf_server
}  // namespace oai

#endif /* Tai_H_ */