/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <vector>
#include <sstream>

#include <osquery/distributed.h>
#include <osquery/enroll.h>
#include <osquery/flags.h>
#include <osquery/registry.h>

#include "osquery/core/json.h"
#include "osquery/remote/serializers/json.h"
#include "osquery/remote/utility.h"

#define START_DELAY_SEC 10

namespace osquery {

FLAG(string,
     distributed_load_query,
     "SELECT * FROM peg;",
     "Query to use to load test distributed query mechanism.  Should be either long running and CPU intensive, or infringe on watchdog memory limit");

class LoadTestDistributedPlugin : public DistributedPlugin {
 public:
  Status setUp() override;

  Status getQueries(std::string& json) override;

  Status writeResults(const std::string& json) override;

 protected:
  std::string query_;
  time_t tStart_ {0};
  time_t tLastRun_ {0};
};

REGISTER(LoadTestDistributedPlugin, "distributed", "loadtest");

Status LoadTestDistributedPlugin::setUp() {
  LOG(WARNING) << "LoadTestDistributedPlugin::setUp()";
  query_ = FLAGS_distributed_load_query;
  tStart_ = time(NULL);
  return Status(0, "OK");
}

Status LoadTestDistributedPlugin::getQueries(std::string& json) {
  LOG(WARNING) << "LoadTestDistributedPlugin::getQueries";
  time_t now = time(NULL);

  // wait a bit to act

  if ((now - tStart_) < START_DELAY_SEC) {
    return Status(0., "OK");
  }

  // run once

  if (tLastRun_ <= 0) {
    tLastRun_ = now;
    std::string id = "1_1";
    json = "{\"queries\": {\"" + id + "\":\"" + query_ + "\"}}"; // TODO: increment id
  }

  return Status(0, "OK");
}

Status LoadTestDistributedPlugin::writeResults(const std::string& json) {
  LOG(WARNING) << "LoadTestDistributedPlugin::writeResults()" << json;

  return Status(0, "OK");
}
}
