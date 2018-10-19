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

#include <string>
#include <vector>

#include <osquery/plugin.h>
#include <osquery/query.h>
#include <osquery/status.h>

namespace osquery {

/**
 * @brief Small struct containing the state of a distributed query
 */
struct DistributedQueryResult {
 public:
  DistributedQueryResult() {}
  DistributedQueryResult(std::string qid, std::string q)
    : id(qid), query(q),  results(), columns(), status(-1) {}

  std::string id;
  std::string query;
  QueryData results;
  ColumnNames columns;
  Status status;
};

class DistributedPlugin : public Plugin {
 public:
  /**
   * @brief Get the queries to be executed
   *
   * Consider the following example JSON which represents the expected format
   *
   * @code{.json}
   *   {
   *     "queries": {
   *       "id1": "select * from osquery_info",
   *       "id2": "select * from osquery_schedule"
   *     }
   *   }
   * @endcode
   *
   * @param json is the string to populate the queries data structure with
   * @return a Status indicating the success or failure of the operation
   */
  virtual Status getQueries(std::string& json) = 0;

  /**
   * @brief Write the results that were executed
   *
   * Consider the following JSON which represents the format that will be used:
   *
   * @code{.json}
   *   {
   *     "queries": {
   *       "id1": [
   *         {
   *           "col1": "val1",
   *           "col2": "val2"
   *         },
   *         {
   *           "col1": "val1",
   *           "col2": "val2"
   *         }
   *       ],
   *       "id2": [
   *         {
   *           "col1": "val1",
   *           "col2": "val2"
   *         }
   *       ]
   *     }
   *   }
   * @endcode
   *
   * @param json is the results data to write
   * @return a Status indicating the success or failure of the operation
   */
  virtual Status writeResults(const std::string& json) = 0;

  /// Main entrypoint for distirbuted plugin requests
  Status call(const PluginRequest& request, PluginResponse& response) override;
};

/**
 * @brief Class for managing the set of distributed queries to execute
 *
 * Consider the following workflow example, without any error handling
 *
 * @code{.cpp}
 *   auto dist = Distributed();
 *   while (true) {
 *     dist.pullUpdates();
 *     if (dist.getPendingQueryCount() > 0) {
 *       dist.runQueries();
 *     }
 *   }
 * @endcode
 */
class Distributed {
 public:
  /// Default constructor
  Distributed() {}

  /// Retrieve queued queries from a remote server
  Status pullUpdates();

  /// Get the number of queries which are waiting to be executed
  size_t getPendingQueryCount();

  /// Get the number of results which are waiting to be flushed
  size_t getCompletedCount();

  /// Serialize result data into a JSON string and clear the results
  Status serializeResults(std::string& json);

  /// Process and execute queued queries
  Status runQueries();

  // Getter for ID of currently executing request
  // NOTE referenced externally by Carver
  static std::string getCurrentRequestId();

 protected:
  /**
   * @brief Process several queries from a distributed plugin
   *
   * Given a response from a distributed plugin, parse the results and enqueue
   * them in the internal state of the class
   *
   * @param work is the string from DistributedPlugin::getQueries
   * @return a Status indicating the success or failure of the operation
   */
  Status acceptWork(const std::string& work);

  /**
   * @brief Pop a request object off of the queries_ member
   *
   * @return a DistributedQueryRequest object which needs to be executed
   */
//  DistributedQueryRequest popRequest();

  /**
   * @brief Queue a result to be batch sent to the server
   *
   * @param result is a DistributedQueryResult object to be sent to the server
   */
//  void addResult(const DistributedQueryResult& result);

  /**
   * @brief Flush all of the collected results to the server
   */
  Status flushCompleted();

  Status passesDiscovery(const JSON &doc);
  Status populateResultState(const JSON &doc, Status discoveryStatus);
  void reportInterruptedWork();

  // Setter for ID of currently executing request
//  static void setCurrentRequestId(const std::string& cReqId);

  std::vector<DistributedQueryResult> results_;

  // ID of the currently executing query
  static std::string currentRequestId_;

 private:
  friend class DistributedTests;
  FRIEND_TEST(DistributedTests, test_workflow);
};
}
