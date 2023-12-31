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

#pragma once

#include "logger_base.hpp"

static const std::string Nef_App    = "nef_app";
static const std::string Nef_Sbi    = "nef_sbi";
static const std::string Nef_System = "system ";

class Logger {
 public:
  static void init(
      const std::string& name, bool log_stdout, bool log_rot_file) {
    oai::logger::logger_registry::register_logger(
        name, Nef_App, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, Nef_Sbi, log_stdout, log_rot_file);
    oai::logger::logger_registry::register_logger(
        name, Nef_System, log_stdout, log_rot_file);
  }

  static const oai::logger::printf_logger& nef_app() {
    return oai::logger::logger_registry::get_logger(Nef_App);
  }

  static const oai::logger::printf_logger& nef_sbi() {
    return oai::logger::logger_registry::get_logger(Nef_Sbi);
  }

  static const oai::logger::printf_logger& system() {
    return oai::logger::logger_registry::get_logger(Nef_System);
  }
};
