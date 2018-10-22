/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <iostream>

#include <gtest/gtest.h>

#include <osquery/core.h>
#include <osquery/distributed.h>
#include <osquery/enroll.h>
#include <osquery/registry_factory.h>
#include <osquery/sql.h>

#include "osquery/core/json.h"
#include "osquery/sql/sqlite_util.h"
#include "osquery/tests/test_additional_util.h"
#include "osquery/tests/test_util.h"

DECLARE_string(distributed_tls_read_endpoint);
DECLARE_string(distributed_tls_write_endpoint);

namespace osquery {

class DistributedTests : public testing::Test {
 protected:
  void TearDown() override {
    stopServer();
  }

  void startServer() {
    TLSServerRunner::start();
    TLSServerRunner::setClientConfig();
    clearNodeKey();

    distributed_tls_read_endpoint_ =
        Flag::getValue("distributed_tls_read_endpoint");
    Flag::updateValue("distributed_tls_read_endpoint", "/distributed_read");

    distributed_tls_write_endpoint_ =
        Flag::getValue("distributed_tls_write_endpoint");
    Flag::updateValue("distributed_tls_write_endpoint", "/distributed_write");

    Registry::get().setActive("distributed", "tls");
    server_started_ = true;
  }
  void stopServer() {
    if (server_started_) {
      TLSServerRunner::stop();
      TLSServerRunner::unsetClientConfig();
      clearNodeKey();

      Flag::updateValue("distributed_tls_read_endpoint",
                        distributed_tls_read_endpoint_);
      Flag::updateValue("distributed_tls_write_endpoint",
                        distributed_tls_write_endpoint_);
    }
  }

 protected:
  std::string distributed_tls_read_endpoint_;
  std::string distributed_tls_write_endpoint_;

 private:
  bool server_started_{false};
};

TEST_F(DistributedTests, test_workflow) {
  startServer();

  auto dist = Distributed();
  auto s = dist.pullUpdates();
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(0U, dist.numDistWrites());

  EXPECT_EQ(dist.getPendingQueryCount(), 2U);
  EXPECT_EQ(dist.results_.size(), 2U);
  s = dist.runQueries();
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");

  EXPECT_EQ(dist.getPendingQueryCount(), 0U);
  EXPECT_EQ(dist.results_.size(), 0U);

  EXPECT_EQ(1U, dist.numDistWrites());
  EXPECT_EQ(1U, dist.numDistReads());
}

static std::string strQueriesInterruptedJson =
    "{\"queries\":{\"99_1\":\"SELECT * FROM time\"}}";

/*
 * At startup, Distributed should check 'distributed_work' key and
 * report status interrupted (9) for all queries.  Here we make
 * sure the 'distributed_work' value is removed after pullUpdates().
 */
TEST_F(DistributedTests, test_report_interrupted) {
  startServer();

  setDatabaseValue(
      kPersistentSettings, "distributed_work", strQueriesInterruptedJson);

  auto dist = Distributed();
  auto s = dist.pullUpdates();
  EXPECT_TRUE(s.ok());

  EXPECT_EQ(1U, dist.numDistWrites());
  EXPECT_EQ(1U, dist.numDistReads());

  std::string strval;
  getDatabaseValue(kPersistentSettings, "distributed_work", strval);

  // should be replaced by server configured queries pullUpdates() received.
  EXPECT_FALSE(strQueriesInterruptedJson == strval);

  // finish up so there isn't DB state left for other tests
  dist.runQueries();
}

/*
 * If a distributed query contains discovery queries:
 *  - If all queries return more than zero rows, run 'queries'.  Otherwise,
 * return empty results.
 */
TEST_F(DistributedTests, test_discovery) {
  static const std::string strNoDiscoveryQueriesJson =
      "{\"discovery\":{\"dos\":\"SELECT * FROM time WHERE year > "
      "1900\"},\"queries\":{\"1A\":\"SELECT year FROM time\"}}";
  static const std::string strDiscoveryQueriesJson =
      "{\"discovery\":{\"uno\":\"SELECT * FROM time WHERE "
      "year=1902\",\"dos\":\"SELECT * FROM time WHERE year > "
      "1900\"},\"queries\":{\"1A\":\"SELECT year FROM time\"}}";

  startServer();
  auto& rf = RegistryFactory::get();
  auto status = rf.setActive("distributed", "mock");
  EXPECT_TRUE(status.ok());
  if (!status.ok()) {
    return;
  }

  PluginResponse response;
  status = Registry::call(
      "distributed",
      {{"action", "setMockReadValue"}, {"value", strDiscoveryQueriesJson}},
      response);

  auto dist = Distributed();
  auto s = dist.pullUpdates();
  EXPECT_TRUE(s.ok());

  s = dist.runQueries();
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");

  response = PluginResponse();
  status =
      Registry::call("distributed", {{"action", "getMockWrites"}}, response);

  EXPECT_EQ(1U, dist.numDistWrites());
  EXPECT_EQ(1U, dist.numDistReads());

  // discovery should fail, so result should have zero rows

  auto response_json1 = response[0]["W_0"];

  // no discovery, should have 1 row

  status = Registry::call(
      "distributed",
      {{"action", "setMockReadValue"}, {"value", strNoDiscoveryQueriesJson}},
      response);

  dist.pullUpdates();
  dist.runQueries();

  response = PluginResponse();
  status =
      Registry::call("distributed", {{"action", "getMockWrites"}}, response);

  auto response_json2 = response[0]["W_1"];

  EXPECT_NE(response_json1, response_json2);
}

} // namespace osquery
