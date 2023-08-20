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
 * RequestedQosMonitoringParameter_anyOf.h
 *
 *
 */

#ifndef RequestedQosMonitoringParameter_anyOf_H_
#define RequestedQosMonitoringParameter_anyOf_H_

#include <nlohmann/json.hpp>

namespace oai {
namespace pcf {
namespace model {

/// <summary>
///
/// </summary>
class RequestedQosMonitoringParameter_anyOf {
 public:
  RequestedQosMonitoringParameter_anyOf();
  virtual ~RequestedQosMonitoringParameter_anyOf() = default;

  enum class eRequestedQosMonitoringParameter_anyOf {
    // To have a valid default value.
    // Avoiding name clashes with user defined
    // enum values
    INVALID_VALUE_OPENAPI_GENERATED = 0,
    DOWNLINK,
    UPLINK,
    ROUND_TRIP
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

  bool operator==(const RequestedQosMonitoringParameter_anyOf& rhs) const;
  bool operator!=(const RequestedQosMonitoringParameter_anyOf& rhs) const;

  /////////////////////////////////////////////
  /// RequestedQosMonitoringParameter_anyOf members

  RequestedQosMonitoringParameter_anyOf::eRequestedQosMonitoringParameter_anyOf
  getValue() const;
  void setValue(RequestedQosMonitoringParameter_anyOf::
                    eRequestedQosMonitoringParameter_anyOf value);

  friend void to_json(
      nlohmann::json& j, const RequestedQosMonitoringParameter_anyOf& o);
  friend void from_json(
      const nlohmann::json& j, RequestedQosMonitoringParameter_anyOf& o);

 protected:
  RequestedQosMonitoringParameter_anyOf::eRequestedQosMonitoringParameter_anyOf
      m_value = RequestedQosMonitoringParameter_anyOf::
          eRequestedQosMonitoringParameter_anyOf::
              INVALID_VALUE_OPENAPI_GENERATED;
};

}  // namespace model
}  // namespace pcf
}  // namespace oai
#endif /* RequestedQosMonitoringParameter_anyOf_H_ */
