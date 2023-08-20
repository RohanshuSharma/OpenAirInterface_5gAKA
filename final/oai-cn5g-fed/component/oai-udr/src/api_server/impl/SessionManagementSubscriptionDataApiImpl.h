/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */
/**
 * Nudr_DataRepository API OpenAPI file
 * Unified Data Repository Service. © 2020, 3GPP Organizational Partners (ARIB,
 * ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 2.1.2
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

/*
 * SessionManagementSubscriptionDataApiImpl.h
 *
 *
 */

#ifndef SESSION_MANAGEMENT_SUBSCRIPTION_DATA_API_IMPL_H_
#define SESSION_MANAGEMENT_SUBSCRIPTION_DATA_API_IMPL_H_

#include <SessionManagementSubscriptionDataApi.h>
#include <pistache/http.h>
#include <pistache/optional.h>

#include "SessionManagementSubscriptionData.h"
#include "Snssai.h"
#include "udr_app.hpp"

namespace oai::udr::api {

using namespace oai::udr::model;
using namespace oai::udr::app;

class SessionManagementSubscriptionDataApiImpl
    : public oai::udr::api::SessionManagementSubscriptionDataApi {
 private:
  udr_app* m_udr_app;
  std::string m_address;

 public:
  SessionManagementSubscriptionDataApiImpl(
      std::shared_ptr<Pistache::Rest::Router>, udr_app* udr_app_inst,
      std::string address);
  ~SessionManagementSubscriptionDataApiImpl() {}

  void query_sm_data(
      const std::string& ueId, const std::string& servingPlmnId,
      const Pistache::Optional<Snssai>& singleNssai,
      const Pistache::Optional<std::string>& dnn,
      const Pistache::Optional<std::vector<std::string>>& fields,
      const Pistache::Optional<std::string>& supportedFeatures,
      const Pistache::Optional<Pistache::Http::Header::Raw>& ifNoneMatch,
      const Pistache::Optional<Pistache::Http::Header::Raw>& ifModifiedSince,
      Pistache::Http::ResponseWriter& response);
  void query_sm_data(Pistache::Http::ResponseWriter& response);
  void create_sm_data(
      const std::string& ueId, const std::string& servingPlmnId,
      SessionManagementSubscriptionData& subscriptionData,
      Pistache::Http::ResponseWriter& response);
  void put_sm_data(
      const std::string& ueId, const std::string& servingPlmnId,
      SessionManagementSubscriptionData& subscriptionData,
      Pistache::Http::ResponseWriter& response);
  void delete_sm_data(
      const std::string& ueId, const std::string& servingPlmnId,
      const Pistache::Optional<Snssai>& singleNssai,
      Pistache::Http::ResponseWriter& response);
};

}  // namespace oai::udr::api

#endif
