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
 * FailureCode.h
 *
 * Possible values are   - UNK_RULE_ID: Indicates that the pre-provisioned PCC
 * rule could not be successfully activated because the PCC rule identifier is
 * unknown to the SMF.   - RA_GR_ERR: Indicate that the PCC rule could not be
 * successfully installed or enforced because the Rating Group specified within
 * the Charging Data policy decision which the PCC rule refers to is unknown or,
 * invalid.   - SER_ID_ERR: Indicate that the PCC rule could not be successfully
 * installed or enforced because the Service Identifier specified within the
 * Charging Data policy decision which the PCC rule refers to is invalid,
 * unknown, or not applicable to the service being charged.   - NF_MAL: Indicate
 * that the PCC rule could not be successfully installed (for those provisioned
 * from the PCF) or activated (for those pre-defined in SMF) or enforced (for
 * those already successfully installed) due to SMF/UPF malfunction.   -
 * RES_LIM: Indicate that the PCC rule could not be successfully installed (for
 * those provisioned from PCF) or activated (for those pre-defined in SMF) or
 * enforced (for those already successfully installed) due to a limitation of
 * resources at the SMF/UPF.   - MAX_NR_QoS_FLOW: Indicate that the PCC rule
 * could not be successfully installed (for those provisioned from PCF) or
 * activated (for those pre-defined in SMF) or enforced (for those already
 * successfully installed) due to the fact that the maximum number of QoS flows
 * has been reached for the PDU session.   - MISS_FLOW_INFO: Indicate that the
 * PCC rule could not be successfully installed or enforced because neither the
 * \&quot;flowInfos\&quot; attribute nor the \&quot;appId\&quot; attribute is
 * specified within the PccRule data structure by the PCF during the first
 * install request of the PCC rule.   - RES_ALLO_FAIL: Indicate that the PCC
 * rule could not be successfully installed or maintained since the QoS flow
 * establishment/modification failed, or the QoS flow was released.   -
 * UNSUCC_QOS_VAL: indicate that the QoS validation has failed or when
 * Guaranteed Bandwidth &gt; Max-Requested-Bandwidth.   - INCOR_FLOW_INFO:
 * Indicate that the PCC rule could not be successfully installed or modified at
 * the SMF because the provided flow information is not supported by the network
 * (e.g. the provided IP address(es) or Ipv6 prefix(es) do not correspond to an
 * IP version applicable for the PDU session).   - PS_TO_CS_HAN: Indicate that
 * the PCC rule could not be maintained because of PS to CS handover.   -
 * APP_ID_ERR: Indicate that the rule could not be successfully installed or
 * enforced because the Application Identifier is invalid, unknown, or not
 * applicable to the application required for detection.   - NO_QOS_FLOW_BOUND:
 * Indicate that there is no QoS flow which the SMF can bind the PCC rule(s) to.
 * - FILTER_RES: Indicate that the Flow Information within the
 * \&quot;flowInfos\&quot; attribute cannot be handled by the SMF because any of
 * the restrictions defined in subclause 5.4.2 of 3GPP TS 29.212 was not met. -
 * MISS_REDI_SER_ADDR: Indicate that the PCC rule could not be successfully
 * installed or enforced at the SMF because there is no valid Redirect Server
 * Address within the Traffic Control Data policy decision which the PCC rule
 * refers to provided by the PCF and no preconfigured redirection address for
 * this PCC rule at the SMF.   - CM_END_USER_SER_DENIED: Indicate that the
 * charging system denied the service request due to service restrictions (e.g.
 * terminate rating group) or limitations related to the end-user, for example
 * the end-user&#39;s account could not cover the requested service.   -
 * CM_CREDIT_CON_NOT_APP: Indicate that the charging system determined that the
 * service can be granted to the end user but no further credit control is
 * needed for the service (e.g. service is free of charge or is treated for
 * offline charging).   - CM_AUTH_REJ: Indicate that the charging system denied
 * the service request in order to terminate the service for which credit is
 * requested.   - CM_USER_UNK: Indicate that the specified end user could not be
 * found in the charging system.   - CM_RAT_FAILED: Indicate that the charging
 * system cannot rate the service request due to insufficient rating input,
 * incorrect AVP combination or due to an attribute or an attribute value that
 * is not recognized or supported in the rating.   - UE_STA_SUSP: Indicates that
 * the UE is in suspend state.
 */

#ifndef FailureCode_H_
#define FailureCode_H_

#include "FailureCode_anyOf.h"
#include <nlohmann/json.hpp>

namespace oai {
namespace pcf {
namespace model {

/// <summary>
/// Possible values are   - UNK_RULE_ID: Indicates that the pre-provisioned PCC
/// rule could not be successfully activated because the PCC rule identifier is
/// unknown to the SMF.   - RA_GR_ERR: Indicate that the PCC rule could not be
/// successfully installed or enforced because the Rating Group specified within
/// the Charging Data policy decision which the PCC rule refers to is unknown
/// or, invalid.   - SER_ID_ERR: Indicate that the PCC rule could not be
/// successfully installed or enforced because the Service Identifier specified
/// within the Charging Data policy decision which the PCC rule refers to is
/// invalid, unknown, or not applicable to the service being charged.   -
/// NF_MAL: Indicate that the PCC rule could not be successfully installed (for
/// those provisioned from the PCF) or activated (for those pre-defined in SMF)
/// or enforced (for those already successfully installed) due to SMF/UPF
/// malfunction.   - RES_LIM: Indicate that the PCC rule could not be
/// successfully installed (for those provisioned from PCF) or activated (for
/// those pre-defined in SMF) or enforced (for those already successfully
/// installed) due to a limitation of resources at the SMF/UPF.   -
/// MAX_NR_QoS_FLOW: Indicate that the PCC rule could not be successfully
/// installed (for those provisioned from PCF) or activated (for those
/// pre-defined in SMF) or enforced (for those already successfully installed)
/// due to the fact that the maximum number of QoS flows has been reached for
/// the PDU session.   - MISS_FLOW_INFO: Indicate that the PCC rule could not be
/// successfully installed or enforced because neither the
/// \&quot;flowInfos\&quot; attribute nor the \&quot;appId\&quot; attribute is
/// specified within the PccRule data structure by the PCF during the first
/// install request of the PCC rule.   - RES_ALLO_FAIL: Indicate that the PCC
/// rule could not be successfully installed or maintained since the QoS flow
/// establishment/modification failed, or the QoS flow was released.   -
/// UNSUCC_QOS_VAL: indicate that the QoS validation has failed or when
/// Guaranteed Bandwidth &gt; Max-Requested-Bandwidth.   - INCOR_FLOW_INFO:
/// Indicate that the PCC rule could not be successfully installed or modified
/// at the SMF because the provided flow information is not supported by the
/// network (e.g. the provided IP address(es) or Ipv6 prefix(es) do not
/// correspond to an IP version applicable for the PDU session).   -
/// PS_TO_CS_HAN: Indicate that the PCC rule could not be maintained because of
/// PS to CS handover.   - APP_ID_ERR: Indicate that the rule could not be
/// successfully installed or enforced because the Application Identifier is
/// invalid, unknown, or not applicable to the application required for
/// detection.   - NO_QOS_FLOW_BOUND: Indicate that there is no QoS flow which
/// the SMF can bind the PCC rule(s) to.   - FILTER_RES: Indicate that the Flow
/// Information within the \&quot;flowInfos\&quot; attribute cannot be handled
/// by the SMF because any of the restrictions defined in subclause 5.4.2 of
/// 3GPP TS 29.212 was not met.   - MISS_REDI_SER_ADDR: Indicate that the PCC
/// rule could not be successfully installed or enforced at the SMF because
/// there is no valid Redirect Server Address within the Traffic Control Data
/// policy decision which the PCC rule refers to provided by the PCF and no
/// preconfigured redirection address for this PCC rule at the SMF.   -
/// CM_END_USER_SER_DENIED: Indicate that the charging system denied the service
/// request due to service restrictions (e.g. terminate rating group) or
/// limitations related to the end-user, for example the end-user&#39;s account
/// could not cover the requested service.   - CM_CREDIT_CON_NOT_APP: Indicate
/// that the charging system determined that the service can be granted to the
/// end user but no further credit control is needed for the service (e.g.
/// service is free of charge or is treated for offline charging).   -
/// CM_AUTH_REJ: Indicate that the charging system denied the service request in
/// order to terminate the service for which credit is requested.   -
/// CM_USER_UNK: Indicate that the specified end user could not be found in the
/// charging system.   - CM_RAT_FAILED: Indicate that the charging system cannot
/// rate the service request due to insufficient rating input, incorrect AVP
/// combination or due to an attribute or an attribute value that is not
/// recognized or supported in the rating.   - UE_STA_SUSP: Indicates that the
/// UE is in suspend state.
/// </summary>
class FailureCode {
 public:
  FailureCode();
  virtual ~FailureCode() = default;

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

  bool operator==(const FailureCode& rhs) const;
  bool operator!=(const FailureCode& rhs) const;

  /////////////////////////////////////////////
  /// FailureCode members

  FailureCode_anyOf getValue() const;
  void setValue(FailureCode_anyOf value);
  FailureCode_anyOf::eFailureCode_anyOf getEnumValue() const;
  void setEnumValue(FailureCode_anyOf::eFailureCode_anyOf value);
  friend void to_json(nlohmann::json& j, const FailureCode& o);
  friend void from_json(const nlohmann::json& j, FailureCode& o);
  friend void to_json(nlohmann::json& j, const FailureCode_anyOf& o);
  friend void from_json(const nlohmann::json& j, FailureCode_anyOf& o);

 protected:
  FailureCode_anyOf m_value;
};

}  // namespace model
}  // namespace pcf
}  // namespace oai
#endif /* FailureCode_H_ */
