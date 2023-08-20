/**
 * Nnef_EventExposure
 * NEF Event Exposure Service. © 2021, 3GPP Organizational Partners (ARIB, ATIS,
 * CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.0.5
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */
/*
 * SubscriptionsCollectionApi.h
 *
 *
 */

#ifndef SubscriptionsCollectionApi_H_
#define SubscriptionsCollectionApi_H_

#include <pistache/http.h>
#include <pistache/http_headers.h>
#include <pistache/router.h>

#include <optional>
#include <string>
#include <utility>

#include "NefEventExposureSubsc.h"
#include "ProblemDetails.h"

namespace oai::nef::api {

class SubscriptionsCollectionApi {
 public:
  explicit SubscriptionsCollectionApi(
      const std::shared_ptr<Pistache::Rest::Router>& rtr);
  virtual ~SubscriptionsCollectionApi() = default;
  void init();

  static const std::string base;

 private:
  void setupRoutes();

  void create_individual_subcription_handler(
      const Pistache::Rest::Request& request,
      Pistache::Http::ResponseWriter response);
  void subscriptions_collection_api_default_handler(
      const Pistache::Rest::Request& request,
      Pistache::Http::ResponseWriter response);

  const std::shared_ptr<Pistache::Rest::Router> router;

  /// <summary>
  /// Helper function to handle unexpected Exceptions during Parameter parsing
  /// and validation. May be overridden to return custom error formats. This is
  /// called inside a catch block. Important: When overriding, do not call
  /// `throw ex;`, but instead use `throw;`.
  /// </summary>
  virtual std::pair<Pistache::Http::Code, std::string> handleParsingException(
      const std::exception& ex) const noexcept;

  /// <summary>
  /// Helper function to handle unexpected Exceptions during processing of the
  /// request in handler functions. May be overridden to return custom error
  /// formats. This is called inside a catch block. Important: When overriding,
  /// do not call `throw ex;`, but instead use `throw;`.
  /// </summary>
  virtual std::pair<Pistache::Http::Code, std::string> handleOperationException(
      const std::exception& ex) const noexcept;

  /// <summary>
  /// subscribe to notifications
  /// </summary>
  /// <remarks>
  ///
  /// </remarks>
  /// <param name="nefEventExposureSubsc"></param>
  virtual void create_individual_subcription(
      const oai::nef::model::NefEventExposureSubsc& nefEventExposureSubsc,
      Pistache::Http::ResponseWriter& response) = 0;
};

}  // namespace oai::nef::api

#endif /* SubscriptionsCollectionApi_H_ */
