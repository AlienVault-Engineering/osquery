/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <ctime>

#include <osquery/core.h>
#include <osquery/flags.h>
#include <osquery/system.h>
#include <osquery/tables.h>

#include "osquery/core/hashing.h"

namespace osquery {

namespace tables {

#define ROW_COUNT 100

void doSomething()
{
  std::string content = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
  for (int i=0; i < 10000; i++) {
    for (int j=0; j < 50000; j++) {
      Hash hash(HASH_TYPE_SHA256);
      hash.update(content.c_str(), content.size());
      auto new_hash = hash.digest();
    }
  }
}

QueryData genPeg(QueryContext& context) {
  QueryData results;
  for (int i=0; i < ROW_COUNT; i++) {
    Row r;
    r["ts1"] = INTEGER(time(NULL));
    doSomething();
    r["ts2"] = INTEGER(time(NULL));
    results.push_back(r);
  }

  return results;
}
} // namespace tables
} // namespace osquery
