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

/*
 * N1N2MessageCollectionDocumentApiImpl.h
 *
 *
 */

#ifndef N1_N2_MESSAGE_COLLECTION_DOCUMENT_API_IMPL_H_
#define N1_N2_MESSAGE_COLLECTION_DOCUMENT_API_IMPL_H_

#include <pistache/endpoint.h>
#include <pistache/http.h>
#include <pistache/router.h>
#include <memory>

#include <N1N2MessageCollectionDocumentApi.h>

#include <pistache/optional.h>

#include "N1N2MessageTransferError.h"
#include "N1N2MessageTransferReqData.h"
#include "N1N2MessageTransferRspData.h"
#include "ProblemDetails.h"
#include "ProblemDetails_2.h"
#include <string>

#include "amf_app.hpp"
#include "mime_parser.hpp"

namespace oai {
namespace amf {
namespace api {

using namespace oai::amf::model;

class N1N2MessageCollectionDocumentApiImpl
    : public oai::amf::api::N1N2MessageCollectionDocumentApi {
 public:
  N1N2MessageCollectionDocumentApiImpl(
      std::shared_ptr<Pistache::Rest::Router>,
      amf_application::amf_app* amf_app_inst);
  ~N1N2MessageCollectionDocumentApiImpl() {}

  void n1_n2_message_transfer(
      const std::string& ueContextId,
      std::unordered_map<std::string, mime_part>& parts,
      Pistache::Http::ResponseWriter& response);

  void send_response(
      const Pistache::Http::Code& code, const nlohmann::json& response_json,
      Pistache::Http::ResponseWriter& response);

 private:
  amf_application::amf_app* m_amf_app;
};

}  // namespace api
}  // namespace amf
}  // namespace oai

#endif
