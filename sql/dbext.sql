/* ======================================================================== */
/* RelayMail: dbext.sql Version: 0.1.1.3                                    */
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

/*
select char_length(Encrypt('12345',LPad('',128,'0'))) from rdb$database
255 = 364
128 = 216
106 = 172
96 = 172
64 = 128
48 = 108
36 = 88
32 = 88
31 = 64
28 = 64
16 = 64
15 = 44
12 = 44
*/
/*-----------------------------------------------------------------------------------------------*/
create exception P_E$SendMail 'Send Mail error.';
/*-----------------------------------------------------------------------------------------------*/
create descending index Mail_X$MD on P_TChain(MailTime);
/*-----------------------------------------------------------------------------------------------*/
set term ^ ;
/*-----------------------------------------------------------------------------------------------*/
alter procedure P_BKeySz
returns
  (Result Integer)
as
begin
  Result = 256;
  suspend;
end^
/*-----------------------------------------------------------------------------------------------*/
create or alter procedure Mail_Send(
  RecipientId TSenderId,
  Recipient TNdAlias,
  Snd TNdAlias,
  SndId TSenderId,
  A_Subject VarChar(128) CHARACTER SET NONE, /* Client converts Ansi to Utf8 by itself */
  A_Body TMemo,
  Data TBlob)
returns
  (SenderId TSenderId,
   BlockId TBlockId,
   Sender TNdAlias,
   MailTime TimeStamp)
as
  declare A_Cast VarChar(1) = ''; /* DEFAULT CHARACTER of PeopleRelay database */
/*
  declare A_Cast VarChar(1) character set UTF8 = ''; DEFAULT CHARACTER of PeopleRelay database
  NOT NEEDED here - this proc located in the same database.
*/
  declare Result SmallInt;
  declare ErrState TErrState;
  declare SelfHash TChHash;
  declare Alias TNdAlias;

  declare Nonce TNonce;

  declare LoadSig TSig;
  declare Address TAddress;
  declare RandKey TRndPwd;
  declare SndClue TSig;
  declare RcpClue TSig;
  declare Subject TSysStr255;

  declare SndKey TKey; /* Sender public key */
  declare RcpKey TKey; /* Recipient public key */

  declare PvtKey TKey;
  declare A_Data TMemo;
  declare Body TText;
begin
  Result = 0;
  BlockId = uuid_to_Char(gen_uuid());
  MailTime = UTCTime();

  select Alias,PubKey,PvtKey from P_TParams into :Alias,:SndKey,:PvtKey; /* Sender */
  select PubKey from P_TNode where NodeId = :RecipientId into :RcpKey; /* Recipient */
  if (Snd is null or Snd = '') then Sender = Alias; else Sender = Snd;

  if (SndId is null or SndId = '')
  then
    execute procedure P_DefSndId returning_values SenderId;
  else
    SenderId = SndId;

  execute procedure P_DefAddr returning_values Address;
  execute procedure P_GenPwd returning_values RandKey;

  SndClue = rsaEncrypt(256,SndKey,RandKey); -- Sender Public Key
  RcpClue = rsaEncrypt(256,RcpKey,RandKey); -- Recipient Public Key
  Subject = Encrypt(RandKey,A_Subject);
  Body = EncBlob(RandKey,A_Body);
  if(Data is not null) then Data = EncBlob(RandKey,Data);

  A_Data = A_Cast ||
    coalesce(BlockId,'0') || '-' ||
    coalesce(Address,'0') || '-' ||
    coalesce(SenderId,'0') || '-' ||
    coalesce(MailTime,'0') || '-' ||
    coalesce(Sender,'0') || '-' ||
    coalesce(RecipientId,'0') || '-' ||
    coalesce(Recipient,'0') || '-' ||
    coalesce(SndClue,'0') || '-' ||
    coalesce(RcpClue,'0') || '-' ||
    coalesce(Subject,'0') || '-' ||
    coalesce(Body,'0') || '-' ||
    coalesce(Data,'0');
    
  execute procedure P_FindHash(A_Data) returning_values Nonce,SelfHash;

  execute procedure P_BlockSig(SelfHash,PvtKey) returning_values LoadSig;

  execute procedure P_AddBlock(
    :SelfHash,
    :BlockId,
    :Address,
    :SenderId,
    :Nonce,
    :LoadSig,
    :SndKey,
    :MailTime,
    :Sender,
    :RecipientId,
    :Recipient,
    :SndClue,
    :RcpClue,
    :Subject,
    :Body,
    :Data)
    returning_values Result,ErrState;
  if (Result < 0 or ErrState is not null) then exception P_E$SendMail;
end^
/*-----------------------------------------------------------------------------------------------*/
/*
select * from Mail_Receive(0)
*/
create or alter procedure Mail_Receive(ABlockNo TRef)
returns
 (BlockNo TRef,
  BlockId TBlockId,
  MailTime TimeStamp,
  SenderId TNodeId,
  Sender TNdAlias,
  RecipientId TSenderId,
  Recipient TNdAlias,
  Subject VarChar(32),
  Body TMemo,
  Data TBlob)
as
  declare AKey TRndPwd;
  declare RcpClue TSig;
  declare NodeId TNodeId;
  declare A_Subject TSysStr255;
  declare A_Body TText;
  declare RcpKey TKey;
begin
  if (ABlockNo is null or ABlockNo < 0) then ABlockNo = 0;

  select NodeId,PvtKey from P_TParams into :NodeId,:RcpKey;

  for select
        BlockNo,
        BlockId,
        MailTime,
        SenderId,
        Sender,
        RecipientId,
        Recipient,
        RcpClue,
        Subject,
        Body,
        Data
    from
      P_TChain
    where BlockNo > :ABlockNo
      and RecipientId = :NodeId
    into
      :BlockNo,
      :BlockId,
      :MailTime,
      :SenderId,
      :Sender,
      :RecipientId,
      :Recipient,
      :RcpClue,
      :A_Subject,
      :A_Body,
      :Data
  do
    begin
      AKey = rsaDecrypt(256,RcpKey,RcpClue); -- Recipient Private Key
      Subject = Decrypt(AKey,A_Subject);
      Body = DecBlob(AKey,A_Body);
      if(Data is not null) then Data = DecBlob(AKey,Data);
      suspend;
    end
end^
/*-----------------------------------------------------------------------------------------------*/
/*
Get one Received msg.
select * from Mail_Receive1(32)
*/
create or alter procedure Mail_Receive1(ABlockNo TRef)
returns
 (BlockNo TRef,
  BlockId TBlockId,
  MailTime TimeStamp,
  SenderId TNodeId,
  Sender TNdAlias,
  RecipientId TSenderId,
  Recipient TNdAlias,
  Subject VarChar(32),
  Body TMemo,
  Data TBlob)
as
  declare AKey TRndPwd;
  declare RcpClue TSig;
  declare NodeId TNodeId;
  declare A_Subject TSysStr255;
  declare A_Body TText;
  declare RcpKey TKey;
begin
  if (ABlockNo is null or ABlockNo <= 0) then ABlockNo = 1;
  select NodeId,PvtKey from P_TParams into :NodeId,:RcpKey;

  select
    BlockNo,
    BlockId,
    MailTime,
    SenderId,
    Sender,
    RecipientId,
    Recipient,
    RcpClue,
    Subject,
    Body,
    Data
  from
    P_TChain
  where BlockNo = :ABlockNo
    and RecipientId = :NodeId
  into
    :BlockNo,
    :BlockId,
    :MailTime,
    :SenderId,
    :Sender,
    :RecipientId,
    :Recipient,
    :RcpClue,
    :A_Subject,
    :A_Body,
    :Data;

  AKey = rsaDecrypt(256,RcpKey,RcpClue); -- Recipient Private Key
  Subject = Decrypt(AKey,A_Subject);
  Body = DecBlob(AKey,A_Body);
  if(Data is not null) then Data = DecBlob(AKey,Data);
  suspend;
end^
/*-----------------------------------------------------------------------------------------------*/
/*
select * from Mail_Receive(0)
*/
create or alter procedure Mail_Receive_N(ACount TUInt1)
returns
 (BlockNo TRef,
  BlockId TBlockId,
  MailTime TimeStamp,
  SenderId TNodeId,
  Sender TNdAlias,
  RecipientId TSenderId,
  Recipient TNdAlias,
  Subject VarChar(32),
  Body TMemo,
  Data TBlob)
as
  declare ABlockNo TRef;
  declare AKey TRndPwd;
  declare RcpClue TSig;
  declare NodeId TNodeId;
  declare A_Subject TSysStr255;
  declare A_Body TText;
  declare RcpKey TKey;
begin
  ABlockNo = (select Max(BlockNo) from P_TChain) - ACount;
  select NodeId,PvtKey from P_TParams into :NodeId,:RcpKey;

  for select
        BlockNo,
        BlockId,
        MailTime,
        SenderId,
        Sender,
        RecipientId,
        Recipient,
        RcpClue,
        Subject,
        Body,
        Data
    from
      P_TChain
    where BlockNo > :ABlockNo
      and RecipientId = :NodeId
    into
      :BlockNo,
      :BlockId,
      :MailTime,
      :SenderId,
      :Sender,
      :RecipientId,
      :Recipient,
      :RcpClue,
      :A_Subject,
      :A_Body,
      :Data
  do
    begin
      AKey = rsaDecrypt(256,RcpKey,RcpClue); -- Recipient Private Key
      Subject = Decrypt(AKey,A_Subject);
      Body = DecBlob(AKey,A_Body);
      if(Data is not null) then Data = DecBlob(AKey,Data);
      suspend;
    end
end^
/*-----------------------------------------------------------------------------------------------*/
/*
select * from Mail_Received(FROMDATE, TODATE)
select * from Mail_Received(CURRENT_DATE - 1, CURRENT_DATE)
*/
create or alter procedure Mail_Received(FromDate TimeStamp, ToDate TimeStamp)
returns
 (BlockNo TRef,
  BlockId TBlockId,
  MailTime TimeStamp,
  SenderId TNodeId,
  Sender TNdAlias,
  RecipientId TSenderId,
  Recipient TNdAlias,
  Subject VarChar(32),
  Body TMemo,
  Data TBlob)
as
  declare AKey TRndPwd;
  declare RcpClue TSig;
  declare NodeId TNodeId;
  declare A_Subject TSysStr255;
  declare A_Body TText;
  declare RcpKey TKey;
begin
  select NodeId,PvtKey from P_TParams into :NodeId,:RcpKey;

  for select
        BlockNo,
        BlockId,
        MailTime,
        SenderId,
        Sender,
        RecipientId,
        Recipient,
        RcpClue,
        Subject,
        Body,
        Data
    from
      P_TChain
    where (cast(MailTime as DATE) >= :FromDate)
      and (:ToDate is null or cast(MailTime as DATE) <= :ToDate)
      and RecipientId = :NodeId
    into
      :BlockNo,
      :BlockId,
      :MailTime,
      :SenderId,
      :Sender,
      :RecipientId,
      :Recipient,
      :RcpClue,
      :A_Subject,
      :A_Body,
      :Data
  do
    begin
      AKey = rsaDecrypt(256,RcpKey,RcpClue); -- Recipient Private Key
      Subject = Decrypt(AKey,A_Subject);
      Body = DecBlob(AKey,A_Body);
      if(Data is not null) then Data = DecBlob(AKey,Data);
      suspend;
    end
end^
/*-----------------------------------------------------------------------------------------------*/
/*
select * from Mail_Sent(CURRENT_DATE - 1, CURRENT_DATE)
*/                       
create or alter procedure Mail_Sent(FromDate TimeStamp, ToDate TimeStamp)
returns
 (BlockNo TRef,
  BlockId TBlockId,
  MailTime TimeStamp,
  SenderId TNodeId,
  Sender TNdAlias,
  RecipientId TSenderId,
  Recipient TNdAlias,
  Subject VarChar(32),
  Body TMemo,
  Data TBlob)
as
  declare AKey TRndPwd;
  declare SndClue TSig;
  declare A_Subject TSysStr255;
  declare A_Body TText;
  declare SndKey TKey;
begin
  select PvtKey from P_TParams into :SndKey;
  execute procedure P_DefSndId returning_values SenderId;

  for select
        BlockNo,
        BlockId,
        MailTime,
        SenderId,
        Sender,
        RecipientId,
        Recipient,
        SndClue,
        Subject,
        Body,
        Data
    from
      P_TChain
    where (cast(MailTime as DATE) >= :FromDate)
      and (:ToDate is null or cast(MailTime as DATE) <= :ToDate)
      and SenderId = :SenderId
    into
      :BlockNo,
      :BlockId,
      :MailTime,
      :SenderId,
      :Sender,
      :RecipientId,
      :Recipient,
      :SndClue,
      :A_Subject,
      :A_Body,
      :Data
  do
    begin
      AKey = rsaDecrypt(256,SndKey,SndClue); -- Sender Private Key
      Subject = Decrypt(AKey,A_Subject);
      Body = DecBlob(AKey,A_Body);
      if(Data is not null) then Data = DecBlob(AKey,Data);
      suspend;
    end
end^
/*-----------------------------------------------------------------------------------------------*/
/*
Get one Sent msg.
select * from Mail_Sent1(32)
*/
create or alter procedure Mail_Sent1(ABlockNo TRef)
returns
 (BlockNo TRef,
  BlockId TBlockId,
  MailTime TimeStamp,
  SenderId TNodeId,
  Sender TNdAlias,
  RecipientId TSenderId,
  Recipient TNdAlias,
  Subject VarChar(32),
  Body TMemo,
  Data TBlob)
as
  declare AKey TRndPwd;
  declare SndClue TSig;
  declare A_Subject TSysStr255;
  declare A_Body TText;
  declare SndKey TKey;
begin
  if (ABlockNo is null or ABlockNo <= 0) then ABlockNo = 1;
  select PvtKey from P_TParams into :SndKey;
  execute procedure P_DefSndId returning_values SenderId;

  select
      BlockNo,
      BlockId,
      MailTime,
      SenderId,
      Sender,
      RecipientId,
      Recipient,
      SndClue,
      Subject,
      Body,
      Data
  from
    P_TChain
  where BlockNo = :ABlockNo
    and SenderId = :SenderId
  into
    :BlockNo,
    :BlockId,
    :MailTime,
    :SenderId,
    :Sender,
    :RecipientId,
    :Recipient,
    :SndClue,
    :A_Subject,
    :A_Body,
    :Data;

  AKey = rsaDecrypt(256,SndKey,SndClue); -- Sender Private Key
  Subject = Decrypt(AKey,A_Subject);
  Body = DecBlob(AKey,A_Body);
  if(Data is not null) then Data = DecBlob(AKey,Data);
  suspend;
end^
/*-----------------------------------------------------------------------------------------------*/
/*
select * from Mail_Sent_N(16)
*/
create or alter procedure Mail_Sent_N(ACount TUInt1)
returns
 (BlockNo TRef,
  BlockId TBlockId,
  MailTime TimeStamp,
  SenderId TNodeId,
  Sender TNdAlias,
  RecipientId TSenderId,
  Recipient TNdAlias,
  Subject VarChar(32),
  Body TMemo,
  Data TBlob)
as
  declare ABlockNo TRef;
  declare AKey TRndPwd;
  declare SndClue TSig;
  declare A_Subject TSysStr255;
  declare A_Body TText;
  declare SndKey TKey;
begin
  ABlockNo = (select Max(BlockNo) from P_TChain) - ACount;
  select PvtKey from P_TParams into :SndKey;
  execute procedure P_DefSndId returning_values SenderId;

  for select
        BlockNo,
        BlockId,
        MailTime,
        SenderId,
        Sender,
        RecipientId,
        Recipient,
        SndClue,
        Subject,
        Body,
        Data
    from
      P_TChain
    where BlockNo > :ABlockNo
      and SenderId = :SenderId
    into
      :BlockNo,
      :BlockId,
      :MailTime,
      :SenderId,
      :Sender,
      :RecipientId,
      :Recipient,
      :SndClue,
      :A_Subject,
      :A_Body,
      :Data
  do
    begin
      AKey = rsaDecrypt(256,SndKey,SndClue); -- Sender Private Key
      Subject = Decrypt(AKey,A_Subject);
      Body = DecBlob(AKey,A_Body);
      if(Data is not null) then Data = DecBlob(AKey,Data);
      suspend;
    end
end^
/*-----------------------------------------------------------------------------------------------*/
set term ; ^
/*-----------------------------------------------------------------------------------------------*/
create view P_Address(
  RecId,
  NodeId,
  Alias)
as
  select
    RecId,
    NodeId,
    Alias
  from
    P_TNode
  where Enabled = 1
    and Status >= 0;
/*-----------------------------------------------------------------------------------------------*/
create view Mail_SentBrief
as
  select
      BlockNo,
      MailTime,
      Recipient
    from
      P_TChain
    where RecipientId = (select NodeId from P_TParams);
--    order by MailTime desc
/*-----------------------------------------------------------------------------------------------*/
create view Mail_RcvdBrief
as
  select
      BlockNo,
      MailTime,
      Recipient
    from
      P_TChain
    where SenderId = (select DefSenderId from P_TParams);
/*-----------------------------------------------------------------------------------------------*/
/*-----------------------------------------------------------------------------------------------*/
grant select on P_TNode to procedure Mail_Send;
grant select on P_TParams to procedure Mail_Send;
grant execute on procedure P_GenPwd to procedure Mail_Send;
grant execute on procedure P_DefAddr to procedure Mail_Send;
grant execute on procedure P_BlockSig to procedure Mail_Send;
grant execute on procedure P_DefSndId to procedure Mail_Send;
grant execute on procedure P_AddBlock to procedure Mail_Send;
grant execute on procedure P_FindHash to procedure Mail_Send;

--grant usage on exception P_E$SendMail to procedure Mail_Send; fb3

grant select on P_TChain to procedure Mail_Receive;
grant select on P_TParams to procedure Mail_Receive;
--grant execute on function rsaDecrypt to procedure Mail_Receive; fb3
--grant execute on function rsaDecBlob to procedure Mail_Receive;

grant select on P_TChain to procedure Mail_Receive1;
grant select on P_TParams to procedure Mail_Receive1;

grant select on P_TChain to procedure Mail_Receive_N;
grant select on P_TParams to procedure Mail_Receive_N;

grant select on P_TChain to procedure Mail_Received;
grant select on P_TParams to procedure Mail_Received;
--grant execute on function rsaDecrypt to procedure Mail_Received; fb3
--grant execute on function rsaDecBlob to procedure Mail_Received;

grant select on P_TChain to procedure Mail_Sent;
grant select on P_TParams to procedure Mail_Sent;
--grant execute on function rsaDecrypt to procedure Mail_Sent; fb3
--grant execute on function rsaDecBlob to procedure Mail_Sent;

grant select on P_TChain to procedure Mail_Sent1;
grant select on P_TParams to procedure Mail_Sent1;

grant select on P_TChain to procedure Mail_Sent_N;
grant select on P_TParams to procedure Mail_Sent_N;
/*-----------------------------------------------------------------------------------------------*/
grant select on P_TChain to procedure P_PayLoadById;
grant select on P_TParams to procedure P_PayLoadById;
/*-----------------------------------------------------------------------------------------------*/
/*-----------------------------------------------------------------------------------------------*/
grant execute on procedure Mail_Send to P_Client;
grant execute on procedure Mail_Sent to P_Client;
grant execute on procedure Mail_Sent1 to P_Client;
grant execute on procedure Mail_Sent_N to P_Client;

grant execute on procedure Mail_Receive to P_Client;
grant execute on procedure Mail_Receive1 to P_Client;
grant execute on procedure Mail_Received to P_Client;
grant execute on procedure Mail_Receive_N to P_Client;

grant select on P_Address to P_Client;

grant select on Mail_SentBrief to P_Client;
grant select on Mail_RcvdBrief to P_Client;
/*-----------------------------------------------------------------------------------------------*/
