/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <chrono>
#include <memory>
#include <vector>

#include <aws/kinesis/KinesisClient.h>
#include <aws/kinesis/model/PutRecordsRequestEntry.h>

#include <osquery/core.h>
#include <osquery/dispatcher.h>
#include <osquery/logger.h>

#include "osquery/logger/plugins/aws_log_forwarder.h"

namespace osquery {
DECLARE_uint64(aws_kinesis_period);


class InternalKinesisClient : public Aws::Kinesis::KinesisClient {
    public:
        InternalKinesisClient(const Aws::Client::ClientConfiguration &clientConfiguration=Aws::Client::ClientConfiguration())
            : Aws::Kinesis::KinesisClient(clientConfiguration)
            {
                VLOG(1) << "InternalKinesisClient 1";
            }

 	    InternalKinesisClient(const Aws::Auth::AWSCredentials &credentials,
 	                           const Aws::Client::ClientConfiguration &clientConfiguration=Aws::Client::ClientConfiguration())
 	        : Aws::Kinesis::KinesisClient(credentials, clientConfiguration)
 	        {
                VLOG(1) << "InternalKinesisClient 2";
 	        }

 	    InternalKinesisClient(const std::shared_ptr< Aws::Auth::AWSCredentialsProvider > &credentialsProvider,
 	                            const Aws::Client::ClientConfiguration &clientConfiguration=Aws::Client::ClientConfiguration())
 	        : Aws::Kinesis::KinesisClient(credentialsProvider, clientConfiguration)
 	        {
                VLOG(1) << "InternalKinesisClient 3";
 	        }

    protected:
        Aws::Client::JsonOutcome MakeRequest(const Aws::Http::URI &uri,
                                const Aws::AmazonWebServiceRequest &request,
                                Aws::Http::HttpMethod method=Aws::Http::HttpMethod::HTTP_POST,
                                const char *signerName=Aws::Auth::SIGV4_SIGNER) const {
            VLOG(1) << "InternalKinesis MakeRequest";
            return Aws::Kinesis::KinesisClient::MakeRequest(uri, request, method, signerName);
        }

        Aws::Client::JsonOutcome MakeRequest(const Aws::Http::URI &uri,
                                             Aws::Http::HttpMethod method=Aws::Http::HttpMethod::HTTP_POST,
                                             const char *signerName=Aws::Auth::SIGV4_SIGNER,
                                             const char *requestName=nullptr) const {
             VLOG(1) << "InternalKinesis MakeRequest2";
             return Aws::Kinesis::KinesisClient::MakeRequest(uri, method, signerName, requestName);
        }

        Aws::Client::HttpResponseOutcome AttemptExhaustively (const Aws::Http::URI &uri,
                                                              const Aws::AmazonWebServiceRequest &request,
                                                              Aws::Http::HttpMethod httpMethod,
                                                              const char *signerName) const
        {
            VLOG(1) << "FOO! 1";
            return Aws::Kinesis::KinesisClient::AttemptExhaustively(uri, request, httpMethod, signerName);
        }

        Aws::Client::HttpResponseOutcome AttemptExhaustively (const Aws::Http::URI &uri,
                                                              Aws::Http::HttpMethod httpMethod,
                                                              const char *signerName,
                                                              const char *requestName=nullptr) const
        {
            VLOG(1) << "FOO! 2";
            return Aws::Kinesis::KinesisClient::AttemptExhaustively(uri, httpMethod, signerName, requestName);
        }

        Aws::Client::HttpResponseOutcome AttemptOneRequest (const Aws::Http::URI &uri,
                                                            const Aws::AmazonWebServiceRequest &request,
                                                            Aws::Http::HttpMethod httpMethod,
                                                            const char *signerName) const
        {
            VLOG(1) << "FOO! 3";
            return Aws::Kinesis::KinesisClient::AttemptOneRequest(uri, request, httpMethod, signerName);
        }

        Aws::Client::HttpResponseOutcome AttemptOneRequest (const Aws::Http::URI &uri,
                                                           Aws::Http::HttpMethod httpMethod,
                                                           const char *signerName,
                                                           const char *requestName=nullptr) const
        {
            VLOG(1) << "FOO! 4";
            return Aws::Kinesis::KinesisClient::AttemptOneRequest(uri, httpMethod, signerName, requestName);
        }

        Aws::Client::StreamOutcome MakeRequestWithUnparsedResponse (const Aws::Http::URI &uri,
                                                                    const Aws::AmazonWebServiceRequest &request,
                                                                    Aws::Http::HttpMethod method=Aws::Http::HttpMethod::HTTP_POST,
                                                                    const char *signerName=Aws::Auth::SIGV4_SIGNER) const
        {
            VLOG(1) << "FOO! 5";
            return Aws::Kinesis::KinesisClient::MakeRequestWithUnparsedResponse(uri, request, method, signerName);
        }

        Aws::Client::StreamOutcome MakeRequestWithUnparsedResponse (const Aws::Http::URI &uri,
                                                                    Aws::Http::HttpMethod method=Aws::Http::HttpMethod::HTTP_POST,
                                                                    const char *signerName=Aws::Auth::SIGV4_SIGNER,
                                                                    const char *requestName=nullptr) const
        {
            VLOG(1) << "FOO! 6";
            return Aws::Kinesis::KinesisClient::MakeRequestWithUnparsedResponse(uri, method, signerName, requestName);
        }

        virtual void BuildHttpRequest(const Aws::AmazonWebServiceRequest &request,
                                       const std::shared_ptr< Aws::Http::HttpRequest > &httpRequest) const
        {
            VLOG(1) << "InternalKinesisClient - BuildHttpRequest(request, " << httpRequest->GetUri().GetURIString() << ")";
            return Aws::Kinesis::KinesisClient::BuildHttpRequest(request, httpRequest);
        }

};

using IKinesisLogForwarder =
    AwsLogForwarder<Aws::Kinesis::Model::PutRecordsRequestEntry,
                    InternalKinesisClient,
                    Aws::Kinesis::Model::PutRecordsOutcome,
                    Aws::Vector<Aws::Kinesis::Model::PutRecordsResultEntry>>;

class KinesisLogForwarder final : public IKinesisLogForwarder {
 public:
  KinesisLogForwarder(const std::string& name,
                      size_t log_period,
                      size_t max_lines)
      : IKinesisLogForwarder(name, log_period, max_lines) {}

 protected:
  Status internalSetup() override;
  Outcome internalSend(const Batch& batch) override;
  void initializeRecord(Record& record,
                        Aws::Utils::ByteBuffer& buffer) const override;

  size_t getMaxBytesPerRecord() const override;
  size_t getMaxRecordsPerBatch() const override;
  size_t getMaxBytesPerBatch() const override;
  size_t getMaxRetryCount() const override;
  size_t getInitialRetryDelay() const override;
  bool appendNewlineSeparators() const override;

  size_t getFailedRecordCount(Outcome& outcome) const override;
  Result getResult(Outcome& outcome) const override;

 private:
  /// The partition key; ignored if aws_kinesis_random_partition_key is set
  std::string partition_key_;

  FRIEND_TEST(KinesisTests, test_send);
};

class KinesisLoggerPlugin : public LoggerPlugin {
 public:
  KinesisLoggerPlugin() : LoggerPlugin() {}

  Status setUp() override;

  bool usesLogStatus() override {
    return true;
  }

 private:
  void init(const std::string& name,
            const std::vector<StatusLogLine>& log) override;

  Status logString(const std::string& s) override;

  /// Log a status (ERROR/WARNING/INFO) message.
  Status logStatus(const std::vector<StatusLogLine>& log) override;

 private:
  std::shared_ptr<KinesisLogForwarder> forwarder_{nullptr};
};
}
