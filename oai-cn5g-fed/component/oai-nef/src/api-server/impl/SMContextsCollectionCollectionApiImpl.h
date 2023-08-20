/**
 * Nnef_SMContext
 * Nnef SMContext Service. © 2021, 3GPP Organizational Partners (ARIB, ATIS,
 * CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.0.2
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

/*
 * SMContextsCollectionCollectionApiImpl.h
 *
 *
 */

#ifndef SM_CONTEXTS_COLLECTION_COLLECTION_API_IMPL_H_
#define SM_CONTEXTS_COLLECTION_COLLECTION_API_IMPL_H_

#include <SMContextsCollectionCollectionApi.h>
#include <pistache/endpoint.h>
#include <pistache/http.h>
#include <pistache/router.h>

#include <memory>
#include <optional>
#include <string>

#include "ProblemDetails.h"
#include "SmContextCreateData.h"
#include "SmContextCreatedData.h"

namespace oai::nef::api {

using namespace oai::nef::model;

class SMContextsCollectionCollectionApiImpl
    : public oai::nef::api::SMContextsCollectionCollectionApi {
 public:
  explicit SMContextsCollectionCollectionApiImpl(
      const std::shared_ptr<Pistache::Rest::Router>& rtr);
  ~SMContextsCollectionCollectionApiImpl() override = default;

  void create(
      const SmContextCreateData& smContextCreateData,
      Pistache::Http::ResponseWriter& response);
};

}  // namespace oai::nef::api

#endif
