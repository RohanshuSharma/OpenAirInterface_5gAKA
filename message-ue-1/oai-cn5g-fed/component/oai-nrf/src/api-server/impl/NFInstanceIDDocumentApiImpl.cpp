/**
 * NRF NFManagement Service
 * NRF NFManagement Service. © 2019, 3GPP Organizational Partners (ARIB, ATIS,
 * CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.1.0.alpha-1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

#include "NFInstanceIDDocumentApiImpl.h"
#include "3gpp_29.500.h"
#include "ProblemDetails.h"
#include "logger.hpp"
#include "nrf_app.hpp"
#include "nrf_config.hpp"
#include "nrf_profile.hpp"

extern oai::nrf::app::nrf_config nrf_cfg;

namespace oai {
namespace nrf {
namespace api {

using namespace oai::nrf::model;
using namespace oai::nrf::app;
using namespace oai::nrf;

NFInstanceIDDocumentApiImpl::NFInstanceIDDocumentApiImpl(
    std::shared_ptr<Pistache::Rest::Router> rtr, nrf_app* nrf_app_inst,
    std::string address)
    : NFInstanceIDDocumentApi(rtr),
      m_nrf_app(nrf_app_inst),
      m_address(address) {}

//------------------------------------------------------------------------------
void NFInstanceIDDocumentApiImpl::deregister_nf_instance(
    const std::string& nfInstanceID, Pistache::Http::ResponseWriter& response) {
  Logger::nrf_sbi().info(
      "Got a request to de-register a given NF Instance, Instance ID: %s",
      nfInstanceID.c_str());

  int http_code                  = 0;
  ProblemDetails problem_details = {};
  m_nrf_app->handle_deregister_nf_instance(
      nfInstanceID, http_code, 1, problem_details);

  nlohmann::json json_data = {};
  std::string content_type = "application/json";

  if (http_code != HTTP_STATUS_CODE_204_NO_CONTENT) {
    to_json(json_data, problem_details);
    content_type = "application/problem+json";
    // content type
    response.headers().add<Pistache::Http::Header::ContentType>(
        Pistache::Http::Mime::MediaType(content_type));
    response.send(Pistache::Http::Code(http_code), json_data.dump().c_str());
    return;
  } else {
    response.headers().add<Pistache::Http::Header::ContentType>(
        Pistache::Http::Mime::MediaType(content_type));
    response.send(Pistache::Http::Code(http_code));
  }
}

//------------------------------------------------------------------------------
void NFInstanceIDDocumentApiImpl::get_nf_instance(
    const std::string& nfInstanceID, Pistache::Http::ResponseWriter& response) {
  Logger::nrf_sbi().info(
      "Got a request to retrieve the profile of a given NF Instance, Instance "
      "ID: %s",
      nfInstanceID.c_str());

  int http_code                        = 0;
  std::shared_ptr<nrf_profile> profile = {};
  ProblemDetails problem_details       = {};
  m_nrf_app->handle_get_nf_instance(
      nfInstanceID, profile, http_code, 1, problem_details);

  nlohmann::json json_data = {};
  std::string content_type = "application/json";

  if (http_code != HTTP_STATUS_CODE_200_OK) {
    to_json(json_data, problem_details);
    content_type = "application/problem+json";
  } else {
    profile.get()->to_json(json_data);
  }

  // content type
  response.headers().add<Pistache::Http::Header::ContentType>(
      Pistache::Http::Mime::MediaType(content_type));
  response.send(Pistache::Http::Code(http_code), json_data.dump().c_str());
}

//------------------------------------------------------------------------------
void NFInstanceIDDocumentApiImpl::register_nf_instance(
    const std::string& nfInstanceID, const NFProfile& nFProfile,
    const Pistache::Optional<Pistache::Http::Header::Raw>& contentEncoding,
    Pistache::Http::ResponseWriter& response) {
  Logger::nrf_sbi().info(
      "Got a request to register an NF instance/Update an NF instance, "
      "Instance ID: %s",
      nfInstanceID.c_str());

  int http_code                  = 0;
  ProblemDetails problem_details = {};
  m_nrf_app->handle_register_nf_instance(
      nfInstanceID, nFProfile, http_code, 1, problem_details);

  nlohmann::json json_data = {};
  std::string content_type = "application/json";

  if ((http_code != HTTP_STATUS_CODE_200_OK) and
      (http_code != HTTP_STATUS_CODE_201_CREATED) and
      (http_code != HTTP_STATUS_CODE_202_ACCEPTED)) {
    to_json(json_data, problem_details);
    content_type = "application/problem+json";
  } else {
    std::shared_ptr<nrf_profile> profile =
        m_nrf_app->find_nf_profile(nfInstanceID);
    if (profile.get() != nullptr) {
      profile.get()->to_json(json_data);
      // to_json(json_data, nFProfile);
    }

    // Location header
    response.headers().add<Pistache::Http::Header::Location>(
        m_address + base + nrf_cfg.sbi_api_version + "/nf-instances/" +
        nfInstanceID);
  }

  // content type
  response.headers().add<Pistache::Http::Header::ContentType>(
      Pistache::Http::Mime::MediaType(content_type));
  response.send(Pistache::Http::Code(http_code), json_data.dump().c_str());
}

//------------------------------------------------------------------------------
void NFInstanceIDDocumentApiImpl::update_nf_instance(
    const std::string& nfInstanceID, const std::vector<PatchItem>& patchItem,
    Pistache::Http::ResponseWriter& response) {
  Logger::nrf_sbi().info("");
  Logger::nrf_sbi().info(
      "Got a request to update an NF instance, Instance ID: %s",
      nfInstanceID.c_str());

  int http_code                  = 0;
  ProblemDetails problem_details = {};
  m_nrf_app->handle_update_nf_instance(
      nfInstanceID, patchItem, http_code, 1, problem_details);

  nlohmann::json json_data = {};
  std::string content_type = "application/json";

  std::shared_ptr<nrf_profile> profile =
      m_nrf_app->find_nf_profile(nfInstanceID);

  if ((http_code != HTTP_STATUS_CODE_200_OK) and
      (http_code != HTTP_STATUS_CODE_204_NO_CONTENT)) {
    to_json(json_data, problem_details);
    content_type = "application/problem+json";
  } else if (http_code == HTTP_STATUS_CODE_200_OK) {
    if (profile.get() != nullptr)
      // convert the profile to Json
      profile.get()->to_json(json_data);
  }

  Logger::nrf_sbi().debug("Json data: %s", json_data.dump().c_str());

  // content type
  response.headers().add<Pistache::Http::Header::ContentType>(
      Pistache::Http::Mime::MediaType(content_type));

  if (http_code != HTTP_STATUS_CODE_204_NO_CONTENT)
    response.send(Pistache::Http::Code(http_code), json_data.dump().c_str());
  else
    response.send(Pistache::Http::Code(http_code));
}

}  // namespace api
}  // namespace nrf
}  // namespace oai
