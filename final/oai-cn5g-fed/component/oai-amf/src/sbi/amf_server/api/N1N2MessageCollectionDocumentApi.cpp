/**
 * Namf_Communication
 * AMF Communication Service © 2019, 3GPP Organizational Partners (ARIB, ATIS,
 * CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.1.0.alpha-1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

#include "N1N2MessageCollectionDocumentApi.h"
#include "Helpers.h"
#include "logger.hpp"
#include "amf_config.hpp"

extern oai::config::amf_config amf_cfg;

namespace oai {
namespace amf {
namespace api {

using namespace oai::amf::helpers;
using namespace oai::amf::model;

N1N2MessageCollectionDocumentApi::N1N2MessageCollectionDocumentApi(
    std::shared_ptr<Pistache::Rest::Router> rtr) {
  router = rtr;
}

void N1N2MessageCollectionDocumentApi::init() {
  setupRoutes();
}

void N1N2MessageCollectionDocumentApi::setupRoutes() {
  using namespace Pistache::Rest;

  Routes::Post(
      *router,
      base + amf_cfg.sbi_api_version +
          "/ue-contexts/:ueContextId/n1-n2-messages",
      Routes::bind(
          &N1N2MessageCollectionDocumentApi::n1_n2_message_transfer_handler,
          this));

  // Default handler, called when a route is not found
  router->addCustomHandler(Routes::bind(
      &N1N2MessageCollectionDocumentApi::
          n1_n2_message_collection_document_api_default_handler,
      this));
}

void N1N2MessageCollectionDocumentApi::n1_n2_message_transfer_handler(
    const Pistache::Rest::Request& request,
    Pistache::Http::ResponseWriter response) {
  // Getting the path params
  auto ueContextId = request.param(":ueContextId").as<std::string>();
  Logger::amf_server().debug(
      "Received a N1N2MessageTrasfer request with ue_ctx_id %s",
      ueContextId.c_str());
  // Getting the body param

  // simple parser
  mime_parser sp = {};
  sp.parse(request.body());

  std::unordered_map<std::string, mime_part> parts = {};
  sp.get_mime_parts(parts);
  uint8_t size = parts.size();
  Logger::amf_server().debug("Number of MIME parts %d", size);

  // at least 2 parts:Json data and N1/N2 or N1+N2)
  if (size < 2) {
    response.send(Pistache::Http::Code::Bad_Request);
    Logger::amf_server().debug(
        "Bad request: should have at least 2 MIME parts");
    return;
  }

  for (auto it : parts) {
    Logger::amf_server().debug(
        "MIME part: %s (size %d bytes)", it.first.c_str(),
        it.second.body.size());
  }

  try {
    this->n1_n2_message_transfer(ueContextId, parts, response);
  } catch (nlohmann::detail::exception& e) {
    // send a 400 error
    Logger::amf_server().error(
        "Error %s, send a msg with error code 400 to SMF", e.what());
    response.send(Pistache::Http::Code::Bad_Request, e.what());
    return;
  } catch (std::exception& e) {
    // send a 500 error
    Logger::amf_server().error(
        "Error %s, send a msg with error code 500 to SMF", e.what());
    response.send(Pistache::Http::Code::Internal_Server_Error, e.what());
    return;
  }
}

void N1N2MessageCollectionDocumentApi::
    n1_n2_message_collection_document_api_default_handler(
        const Pistache::Rest::Request&,
        Pistache::Http::ResponseWriter response) {
  response.send(
      Pistache::Http::Code::Not_Found, "The requested method does not exist");
}

}  // namespace api
}  // namespace amf
}  // namespace oai
