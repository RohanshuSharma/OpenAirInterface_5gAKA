/**
 * 3gpp-analyticsexposure
 * API for Analytics Exposure. © 2021, 3GPP Organizational Partners (ARIB, ATIS,
 * CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.0.3
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */
/*
 * ExpectedAnalyticsType.h
 *
 * Possible values are   - MOBILITY: Mobility related abnormal behaviour
 * analytics is expected by the consumer.   - COMMUN: Communication related
 * abnormal behaviour analytics is expected by the consumer.   -
 * MOBILITY_AND_COMMUN: Both mobility and communication related abnormal
 * behaviour analytics is expected by the consumer.
 */

#ifndef ExpectedAnalyticsType_H_
#define ExpectedAnalyticsType_H_

#include <nlohmann/json.hpp>

#include "ExpectedAnalyticsType_anyOf.h"

namespace oai::nef::model {

/// <summary>
/// Possible values are   - MOBILITY: Mobility related abnormal behaviour
/// analytics is expected by the consumer.   - COMMUN: Communication related
/// abnormal behaviour analytics is expected by the consumer.   -
/// MOBILITY_AND_COMMUN: Both mobility and communication related abnormal
/// behaviour analytics is expected by the consumer.
/// </summary>
class ExpectedAnalyticsType {
 public:
  ExpectedAnalyticsType();
  virtual ~ExpectedAnalyticsType() = default;

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

  bool operator==(const ExpectedAnalyticsType& rhs) const;
  bool operator!=(const ExpectedAnalyticsType& rhs) const;

  /////////////////////////////////////////////
  /// ExpectedAnalyticsType members

  ExpectedAnalyticsType_anyOf getValue() const;
  void setValue(ExpectedAnalyticsType_anyOf value);
  ExpectedAnalyticsType_anyOf::eExpectedAnalyticsType_anyOf getEnumValue()
      const;
  void setEnumValue(
      ExpectedAnalyticsType_anyOf::eExpectedAnalyticsType_anyOf value);
  friend void to_json(nlohmann::json& j, const ExpectedAnalyticsType& o);
  friend void from_json(const nlohmann::json& j, ExpectedAnalyticsType& o);
  friend void to_json(nlohmann::json& j, const ExpectedAnalyticsType_anyOf& o);
  friend void from_json(
      const nlohmann::json& j, ExpectedAnalyticsType_anyOf& o);

 protected:
  ExpectedAnalyticsType_anyOf m_value;
};

}  // namespace oai::nef::model

#endif /* ExpectedAnalyticsType_H_ */