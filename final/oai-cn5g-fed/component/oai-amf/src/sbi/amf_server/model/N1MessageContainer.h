/**
 * Namf_Communication
 * AMF Communication Service © 2022, 3GPP Organizational Partners (ARIB, ATIS,
 * CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.1.8
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */
/*
 * N1MessageContainer.h
 *
 *
 */

#ifndef N1MessageContainer_H_
#define N1MessageContainer_H_

#include "N1MessageClass.h"
#include "RefToBinaryData.h"
#include <string>
#include <nlohmann/json.hpp>

namespace oai::amf::model {

/// <summary>
///
/// </summary>
class N1MessageContainer {
 public:
  N1MessageContainer();
  virtual ~N1MessageContainer() = default;

  /// <summary>
  /// Validate the current data in the model. Throws a ValidationException on
  /// failure.
  /// </summary>
  void validate() const;

  /// <summary>
  /// Validate the current data in the model. Returns false on error and writes
  /// an error message into the given stringstream.
  /// </summary>
  bool validate(std::stringstream& msg) const;

  /// <summary>
  /// Helper overload for validate. Used when one model stores another model and
  /// calls it's validate. Not meant to be called outside that case.
  /// </summary>
  bool validate(std::stringstream& msg, const std::string& pathPrefix) const;

  bool operator==(const N1MessageContainer& rhs) const;
  bool operator!=(const N1MessageContainer& rhs) const;

  /////////////////////////////////////////////
  /// N1MessageContainer members

  /// <summary>
  ///
  /// </summary>
  oai::amf::model::N1MessageClass getN1MessageClass() const;
  void setN1MessageClass(oai::amf::model::N1MessageClass const& value);
  /// <summary>
  ///
  /// </summary>
  oai::amf::model::RefToBinaryData getN1MessageContent() const;
  void setN1MessageContent(oai::amf::model::RefToBinaryData const& value);
  /// <summary>
  ///
  /// </summary>
  std::string getNfId() const;
  void setNfId(std::string const& value);
  bool nfIdIsSet() const;
  void unsetNfId();
  /// <summary>
  ///
  /// </summary>
  std::string getServiceInstanceId() const;
  void setServiceInstanceId(std::string const& value);
  bool serviceInstanceIdIsSet() const;
  void unsetServiceInstanceId();

  friend void to_json(nlohmann::json& j, const N1MessageContainer& o);
  friend void from_json(const nlohmann::json& j, N1MessageContainer& o);

 protected:
  oai::amf::model::N1MessageClass m_N1MessageClass;

  oai::amf::model::RefToBinaryData m_N1MessageContent;

  std::string m_NfId;
  bool m_NfIdIsSet;
  std::string m_ServiceInstanceId;
  bool m_ServiceInstanceIdIsSet;
};

}  // namespace oai::amf::model

#endif /* N1MessageContainer_H_ */