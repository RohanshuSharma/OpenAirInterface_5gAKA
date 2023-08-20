/**
 * Npcf_SMPolicyControl API
 * Session Management Policy Control Service © 2020, 3GPP Organizational
 * Partners (ARIB, ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.1.1.alpha-5
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */
/*
 * QosFlowUsage_anyOf.h
 *
 *
 */

#ifndef QosFlowUsage_anyOf_H_
#define QosFlowUsage_anyOf_H_

#include <nlohmann/json.hpp>

namespace oai {
namespace pcf {
namespace model {

/// <summary>
///
/// </summary>
class QosFlowUsage_anyOf {
 public:
  QosFlowUsage_anyOf();
  virtual ~QosFlowUsage_anyOf() = default;

  enum class eQosFlowUsage_anyOf {
    // To have a valid default value.
    // Avoiding name clashes with user defined
    // enum values
    INVALID_VALUE_OPENAPI_GENERATED = 0,
    GENERAL,
    IMS_SIG
  };

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

  bool operator==(const QosFlowUsage_anyOf& rhs) const;
  bool operator!=(const QosFlowUsage_anyOf& rhs) const;

  /////////////////////////////////////////////
  /// QosFlowUsage_anyOf members

  QosFlowUsage_anyOf::eQosFlowUsage_anyOf getValue() const;
  void setValue(QosFlowUsage_anyOf::eQosFlowUsage_anyOf value);

  friend void to_json(nlohmann::json& j, const QosFlowUsage_anyOf& o);
  friend void from_json(const nlohmann::json& j, QosFlowUsage_anyOf& o);

 protected:
  QosFlowUsage_anyOf::eQosFlowUsage_anyOf m_value =
      QosFlowUsage_anyOf::eQosFlowUsage_anyOf::INVALID_VALUE_OPENAPI_GENERATED;
};

}  // namespace model
}  // namespace pcf
}  // namespace oai
#endif /* QosFlowUsage_anyOf_H_ */
