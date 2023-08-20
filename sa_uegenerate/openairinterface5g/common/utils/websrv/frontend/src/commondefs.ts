/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this file
 * except in compliance with the License.
 * You may obtain a copy of the License at
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

/*! \file common/utils/websrv/frontend/src/commondefs.ts
 * \brief: implementation of web interface frontend for oai
 * \definitions of constants, enums and interfaces common to the whole frontend  
 * \author:  Yacine  El Mghazli, Francois TABURET
 * \date 2022
 * \version 0.1
 * \company NOKIA BellLabs France
 * \email: yacine.el_mghazli@nokia-bell-labs.com  francois.taburet@nokia-bell-labs.com
 * \note
 * \warning
 */
export enum IArgType {
  boolean = "boolean",
  list = "list",
  loglvl = "loglvl",
  range = "range",
  number = "number",
  string = "string",
  configfile = "configfile",
  simuTypes = "simuTypes",
}

export interface IInfo {
  name: string;
  value: string;
  type: IArgType;
  modifiable: boolean; // set command ?
}

export const route = "oaisoftmodem/";
