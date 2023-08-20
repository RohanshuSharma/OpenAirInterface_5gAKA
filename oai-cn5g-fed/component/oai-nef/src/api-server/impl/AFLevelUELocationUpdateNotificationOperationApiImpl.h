/**
 * 3gpp-mo-lcs-notify
 * API for UE updated location information notification. © 2021, 3GPP
 * Organizational Partners (ARIB, ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights
 * reserved.
 *
 * The version of the OpenAPI document: 1.0.1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

/*
 * AFLevelUELocationUpdateNotificationOperationApiImpl.h
 *
 *
 */

#ifndef AF_LEVEL_UE_LOCATION_UPDATE_NOTIFICATION_OPERATION_API_IMPL_H_
#define AF_LEVEL_UE_LOCATION_UPDATE_NOTIFICATION_OPERATION_API_IMPL_H_

#include <AFLevelUELocationUpdateNotificationOperationApi.h>
#include <pistache/endpoint.h>
#include <pistache/http.h>
#include <pistache/router.h>

#include <memory>
#include <optional>
#include <string>

#include "LocUpdateData.h"
#include "LocUpdateDataReply.h"
#include "ProblemDetails.h"

namespace oai::nef::api {

using namespace oai::nef::model;

class AFLevelUELocationUpdateNotificationOperationApiImpl
    : public oai::nef::api::AFLevelUELocationUpdateNotificationOperationApi {
 public:
  explicit AFLevelUELocationUpdateNotificationOperationApiImpl(
      const std::shared_ptr<Pistache::Rest::Router>& rtr);
  ~AFLevelUELocationUpdateNotificationOperationApiImpl() override = default;

  void root_post(
      const LocUpdateData& locUpdateData,
      Pistache::Http::ResponseWriter& response);
};

}  // namespace oai::nef::api

#endif