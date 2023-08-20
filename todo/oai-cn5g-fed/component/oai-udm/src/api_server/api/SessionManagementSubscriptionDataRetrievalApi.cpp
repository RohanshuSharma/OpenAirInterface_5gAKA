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

#include "SessionManagementSubscriptionDataRetrievalApi.h"
#include "logger.hpp"
#include "Helpers.h"
#include "udm_config.hpp"

extern oai::udm::config::udm_config udm_cfg;

namespace oai {
namespace udm {
namespace api {

using namespace oai::udm::helpers;
using namespace oai::udm::model;
using namespace oai::udm::config;

SessionManagementSubscriptionDataRetrievalApi::
    SessionManagementSubscriptionDataRetrievalApi(
        std::shared_ptr<Pistache::Rest::Router> rtr) {
  router = rtr;
}

void SessionManagementSubscriptionDataRetrievalApi::init() {
  setupRoutes();
}

void SessionManagementSubscriptionDataRetrievalApi::setupRoutes() {
  using namespace Pistache::Rest;

  Routes::Get(
      *router, base + udm_cfg.sbi.api_version + "/:supi/sm-data",
      Routes::bind(
          &SessionManagementSubscriptionDataRetrievalApi::get_sm_data_handler,
          this));

  // Default handler, called when a route is not found
  router->addCustomHandler(Routes::bind(
      &SessionManagementSubscriptionDataRetrievalApi::
          session_management_subscription_data_retrieval_api_default_handler,
      this));
}

void SessionManagementSubscriptionDataRetrievalApi::get_sm_data_handler(
    const Pistache::Rest::Request& request,
    Pistache::Http::ResponseWriter response) {
  Logger::udm_sdm().debug(
      "Received a SessionManagementSubscriptionDataRetrieval query");

  // Getting the path params
  auto supi = request.param(":supi").as<std::string>();

  // Getting the query params
  /*
   * TODO:
  auto supportedFeaturesQuery = request.query().get("supported-features");
  Pistache::Optional<std::string> supportedFeatures;
  if(!supportedFeaturesQuery.isEmpty()){
      std::string value;
      if(fromStringValue(supportedFeaturesQuery.get(), value)){
          supportedFeatures = Pistache::Some(value);
      }
  }
  */
  auto singleNssaiQuery = request.query().get("single-nssai");
  Pistache::Optional<Snssai> singleNssai;
  if (!singleNssaiQuery.isEmpty()) {
    Logger::udm_sdm().debug(
        "singleNssaiQuery: %s", singleNssaiQuery.get().c_str());
    Snssai value;
    if (fromStringValue(singleNssaiQuery.get(), value)) {
      Logger::udm_sdm().debug(
          "SNSSAI SST %d, SD %s", value.getSst(), value.getSd().c_str());
      singleNssai = Pistache::Some(value);
    }
  }

  auto dnnQuery = request.query().get("dnn");
  Pistache::Optional<std::string> dnn;
  if (!dnnQuery.isEmpty()) {
    Logger::udm_sdm().debug("dnnQuery: %s", dnnQuery.get().c_str());
    std::string value;
    if (fromStringValue(dnnQuery.get(), value)) {
      Logger::udm_sdm().debug("DNN: %s", value.c_str());
      dnn = Pistache::Some(value);
    }
  }

  auto plmnIdQuery = request.query().get("plmn-id");
  Pistache::Optional<PlmnId> plmnId;
  if (!plmnIdQuery.isEmpty()) {
    Logger::udm_sdm().debug("plmnIdQuery: %s", plmnIdQuery.get().c_str());
    PlmnId value;
    if (fromStringValue(plmnIdQuery.get(), value)) {
      Logger::udm_sdm().debug(
          "PLMN MCC %s, MNC %s", value.getMcc().c_str(),
          value.getMnc().c_str());
      plmnId = Pistache::Some(value);
    }
  }

  /*
   * TODO:

  // Getting the header params
  auto ifNoneMatch = request.headers().tryGetRaw("If-None-Match");
  auto ifModifiedSince = request.headers().tryGetRaw("If-Modified-Since");
 */
  try {
    // this->get_sm_data(supi, supportedFeatures, singleNssai, dnn, plmnId,
    // ifNoneMatch, ifModifiedSince, response);
    this->get_sm_data(supi, singleNssai, dnn, plmnId, response);
  } catch (nlohmann::detail::exception& e) {
    // send a 400 error
    response.send(Pistache::Http::Code::Bad_Request, e.what());
    return;
  } catch (std::exception& e) {
    // send a 500 error
    response.send(Pistache::Http::Code::Internal_Server_Error, e.what());
    return;
  }
}

void SessionManagementSubscriptionDataRetrievalApi::
    session_management_subscription_data_retrieval_api_default_handler(
        const Pistache::Rest::Request&,
        Pistache::Http::ResponseWriter response) {
  response.send(
      Pistache::Http::Code::Not_Found, "The requested method does not exist");
}

}  // namespace api
}  // namespace udm
}  // namespace oai