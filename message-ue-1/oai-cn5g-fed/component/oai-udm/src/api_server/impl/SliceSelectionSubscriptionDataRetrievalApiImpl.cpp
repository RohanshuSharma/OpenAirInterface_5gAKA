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
 * Nudm_SDM
 * Nudm Subscriber Data Management Service. � 2019, 3GPP Organizational Partners
 * (ARIB, ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 2.1.0.alpha-1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

#include "SliceSelectionSubscriptionDataRetrievalApiImpl.h"

#include "udm_client.hpp"
#include "logger.hpp"
#include "udm_config.hpp"

extern oai::udm::config::udm_config udm_cfg;

namespace oai {
namespace udm {
namespace api {

using namespace oai::udm::model;
using namespace oai::udm::app;
using namespace oai::udm::config;

SliceSelectionSubscriptionDataRetrievalApiImpl::
    SliceSelectionSubscriptionDataRetrievalApiImpl(
        std::shared_ptr<Pistache::Rest::Router> rtr, udm_app* udm_app_inst,
        std::string address)
    : SliceSelectionSubscriptionDataRetrievalApi(rtr) {}

void SliceSelectionSubscriptionDataRetrievalApiImpl::get_nssai(
    const std::string& supi,
    const Pistache::Optional<std::string>& supportedFeatures,
    const Pistache::Optional<PlmnId>& plmnId,
    const Pistache::Optional<Pistache::Http::Header::Raw>& ifNoneMatch,
    const Pistache::Optional<Pistache::Http::Header::Raw>& ifModifiedSince,
    Pistache::Http::ResponseWriter& response) {
  std::string supported_features_str = {};
  if (!supportedFeatures.isEmpty()) {
    supported_features_str = supportedFeatures.get();
  }

  PlmnId plmn_id = {};
  if (!plmnId.isEmpty()) {
    plmn_id = plmnId.get();
  }

  nlohmann::json response_data = {};
  Pistache::Http::Code code    = {};

  long http_code = 0;

  m_udm_app->handle_slice_selection_subscription_data_retrieval(
      supi, response_data, http_code, supported_features_str, plmn_id);

  code = static_cast<Pistache::Http::Code>(http_code);

  // Set content type
  if ((code == Pistache::Http::Code::Created) or
      (code == Pistache::Http::Code::Accepted) or
      (code == Pistache::Http::Code::Ok) or
      (code == Pistache::Http::Code::No_Content)) {
    response.headers().add<Pistache::Http::Header::ContentType>(
        Pistache::Http::Mime::MediaType("application/json"));
  } else {
    response.headers().add<Pistache::Http::Header::ContentType>(
        Pistache::Http::Mime::MediaType("application/problem+json"));
  }

  response.send(code, response_data.dump().c_str());
}

}  // namespace api
}  // namespace udm
}  // namespace oai
