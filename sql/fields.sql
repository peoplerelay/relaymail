/* ======================================================================== */
/* RelayMail: fields.sql Version: 0.1.1.3                                   */
/*                                                                          */
/* Copyright 2017-2018 Aleksei Ilin & Igor Ilin                             */
/*                                                                          */
/* Licensed under the Apache License, Version 2.0 (the "License");          */
/* you may not use this file except in compliance with the License.         */
/* You may obtain a copy of the License at                                  */
/*                                                                          */
/*     http://www.apache.org/licenses/LICENSE-2.0                           */
/*                                                                          */
/* Unless required by applicable law or agreed to in writing, software      */
/* distributed under the License is distributed on an "AS IS" BASIS,        */
/* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. */
/* See the License for the specific language governing permissions and      */
/* limitations under the License.                                           */
/* ======================================================================== */

/*-----------------------------------------------------------------------------------------------*/
/* E Mail Example */
/*-----------------------------------------------------------------------------------------------*/
insert into P_TFields(FieldName,DataType,DefVal,Constr)
  values('MailTime','TimeStamp','CURRENT_TIMESTAMP','not null');

insert into P_TFields(FieldName,DataType,DefVal,Constr)
  values('Sender','TNdAlias','-','not null');

insert into P_TFields(FieldName,DataType,DefVal,Constr)
  values('RecipientId','TSenderId','-','not null');

insert into P_TFields(FieldName,DataType,DefVal,Constr)
  values('Recipient','TNdAlias','-','not null');

insert into P_TFields(FieldName,DataType,DefVal,Constr,Encrypt)
  values('SndClue','TSig','-','not null',1);
insert into P_TFields(FieldName,DataType,DefVal,Constr,Encrypt)
  values('RcpClue','TSig','-','not null',1);

insert into P_TFields(FieldName,DataType,DefVal,Constr,Encrypt)
  values('Subject','TSysStr255','-','not null',1);

insert into P_TFields(FieldName,DataType,DefVal,Constr,Encrypt)
  values('Body','TText','-','not null',1);

insert into P_TFields(FieldName,DataType,DefVal,Constr,Encrypt)
  values('Data','TBlob',null,null,1);
/*-----------------------------------------------------------------------------------------------*/

