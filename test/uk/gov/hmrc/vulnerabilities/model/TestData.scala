/*
 * Copyright 2026 HM Revenue & Customs
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package uk.gov.hmrc.vulnerabilities.model

object TestData:
  object XRayModel:

    lazy val vulnerabilityEntryV1: String =
      """{
        |  "cves" : [ {
        |    "cve" : "CVE-1",
        |    "cvss_v3_score" : 8,
        |    "cvss_v3_vector" : "test"
        |  } ],
        |  "cvss3_max_score" : 8,
        |  "summary" : "This is an exploit",
        |  "severity" : "High",
        |  "severity_source" : "Source",
        |  "vulnerable_component" : "gav://com.testxml.test.core:test-bind:1.5.9",
        |  "component_physical_path" : "service1-1.0.4/some/physical/path",
        |  "impacted_artifact" : "fooBar",
        |  "impact_path" : [ "hello", "world" ],
        |  "path" : "test/slugs/service1/service1_1.0.4_0.0.1.tgz",
        |  "fixed_versions" : [ "1.6.0" ],
        |  "published" : "2022-12-01T00:00:00Z",
        |  "artifact_scan_time" : "2022-12-13T00:00:00Z",
        |  "issue_id" : "XRAY-000003",
        |  "package_type" : "maven",
        |  "provider" : "test",
        |  "description" : "This is an exploit description",
        |  "references" : [ "foo.com", "bar.net" ],
        |  "project_keys" : [ ]
        |}
        |""".stripMargin

    lazy val vulnerabilityEntryV1_X_missingFields: String =
      """{
        |  "cves" : [ {
        |    "cve" : "CVE-1",
        |    "cvss_v3_score" : 8,
        |    "cvss_v3_vector" : "test"
        |  } ],
        |  "cvss3_max_score" : 8,
        |  "summary" : "This is an exploit",
        |  "severity" : "High",
        |  "vulnerable_component" : "gav://com.testxml.test.core:test-bind:1.5.9",
        |  "component_physical_path" : "service1-1.0.4/some/physical/path",
        |  "impacted_artifact" : "fooBar",
        |  "impact_path" : [ "hello", "world" ],
        |  "path" : "test/slugs/service1/service1_1.0.4_0.0.1.tgz",
        |  "fixed_versions" : [ "1.6.0" ],
        |  "published" : "2022-12-01T00:00:00Z",
        |  "artifact_scan_time" : "2022-12-13T00:00:00Z",
        |  "issue_id" : "XRAY-000003",
        |  "package_type" : "maven",
        |  "project_keys" : [ ]
        |}
        |""".stripMargin

    lazy val vuln1JsonV1: String =
      """{
        |  "cves" : [ {
        |    "cve" : "CVE-2021-99999",
        |    "cvss_v3_score" : 7,
        |    "cvss_v3_vector" : "test1"
        |  } ],
        |  "cvss3_max_score" : 7,
        |  "summary" : "This is a lower severity exploit",
        |  "severity" : "High",
        |  "severity_source" : "Source",
        |  "vulnerable_component" : "gav://com.testxml.test.core:test-bind:1.6.8",
        |  "component_physical_path" : "service2-3.0.4/some/physical/path",
        |  "impacted_artifact" : "fooBar",
        |  "impact_path" : [ "hello", "world" ],
        |  "path" : "test/slugs/service2/service2_3.0.4_0.0.1.tgz",
        |  "fixed_versions" : [ "1.6.9" ],
        |  "published" : "2026-05-15T00:00:00Z",
        |  "artifact_scan_time" : "2026-05-15T00:00:00Z",
        |  "issue_id" : "XRAY-000002",
        |  "package_type" : "maven",
        |  "provider" : "test1",
        |  "description" : "This is the first exploit",
        |  "references" : [ "foo.com", "bar.net" ],
        |  "project_keys" : [ ],
        |  "importedBy" : {
        |    "group" : "some-group",
        |    "artefact" : "some-artefact",
        |    "version" : "0.2.0"
        |  }
        |}
        |""".stripMargin

    lazy val vuln2JsonV1: String =
      """
        |{
        |  "cves" : [ {
        |    "cve" : "CVE-2022-12345",
        |    "cvss_v3_score" : 8,
        |    "cvss_v3_vector" : "test2"
        |  } ],
        |  "cvss3_max_score" : 8,
        |  "summary" : "This is a higher severity exploit",
        |  "severity" : "High",
        |  "severity_source" : "Source",
        |  "vulnerable_component" : "gav://com.testxml.test.core:test-bind:1.5.9",
        |  "component_physical_path" : "service2-3.0.4/some/physical/path",
        |  "impacted_artifact" : "fooBar",
        |  "impact_path" : [ "hello", "world" ],
        |  "path" : "test/slugs/service2/service2_3.0.4_0.0.1.tgz",
        |  "fixed_versions" : [ "1.6.0" ],
        |  "published" : "2026-05-15T00:00:00Z",
        |  "artifact_scan_time" : "2026-05-15T00:00:00Z",
        |  "issue_id" : "XRAY-000003",
        |  "package_type" : "maven",
        |  "provider" : "test2",
        |  "description" : "This is the second exploit",
        |  "references" : [ "buzz.com", "fizz.net" ],
        |  "project_keys" : [ ],
        |  "importedBy" : {
        |    "group" : "some-group",
        |    "artefact" : "some-artefact",
        |    "version" : "0.1.0"
        |  }
        |}
        |""".stripMargin


    lazy val vuln1JsonV1xMissingFields: String =
      """{
        |  "cves" : [ {
        |    "cve" : "CVE-2021-99999",
        |    "cvss_v3_score" : 7,
        |    "cvss_v3_vector" : "test1"
        |  } ],
        |  "cvss3_max_score" : 7,
        |  "summary" : "This is a lower severity exploit",
        |  "severity" : "High",
        |  "vulnerable_component" : "gav://com.testxml.test.core:test-bind:1.6.8",
        |  "component_physical_path" : "service2-3.0.4/some/physical/path",
        |  "impacted_artifact" : "fooBar",
        |  "impact_path" : [ "hello", "world" ],
        |  "path" : "test/slugs/service2/service2_3.0.4_0.0.1.tgz",
        |  "fixed_versions" : [ "1.6.9" ],
        |  "published" : "2026-05-15T00:00:00Z",
        |  "artifact_scan_time" : "2026-05-15T00:00:00Z",
        |  "issue_id" : "XRAY-000002",
        |  "package_type" : "maven",
        |  "project_keys" : [ ],
        |  "importedBy" : {
        |    "group" : "some-group",
        |    "artefact" : "some-artefact",
        |    "version" : "0.2.0"
        |  }
        |}
        |""".stripMargin

    lazy val vuln2JsonV1xMissingFields: String =
      """
        |{
        |  "cves" : [ {
        |    "cve" : "CVE-2022-12345",
        |    "cvss_v3_score" : 8,
        |    "cvss_v3_vector" : "test2"
        |  } ],
        |  "cvss3_max_score" : 8,
        |  "summary" : "This is a higher severity exploit",
        |  "severity" : "High",
        |  "vulnerable_component" : "gav://com.testxml.test.core:test-bind:1.5.9",
        |  "component_physical_path" : "service2-3.0.4/some/physical/path",
        |  "impacted_artifact" : "fooBar",
        |  "impact_path" : [ "hello", "world" ],
        |  "path" : "test/slugs/service2/service2_3.0.4_0.0.1.tgz",
        |  "fixed_versions" : [ "1.6.0" ],
        |  "published" : "2026-05-15T00:00:00Z",
        |  "artifact_scan_time" : "2026-05-15T00:00:00Z",
        |  "issue_id" : "XRAY-000003",
        |  "package_type" : "maven",
        |  "project_keys" : [ ],
        |  "importedBy" : {
        |    "group" : "some-group",
        |    "artefact" : "some-artefact",
        |    "version" : "0.1.0"
        |  }
        |}
        |""".stripMargin

  object MongoModel:
    lazy val vulnerabilityEntryV1Mongo: String =
      """
        |   {
        |      "cves": [
        |        {
        |          "cve": "CVE-2022-12345",
        |          "cvss_v3_score": 8,
        |          "cvss_v3_vector": "test"
        |        }
        |      ],
        |      "cvss3_max_score": 8,
        |      "summary": "This is an exploit",
        |      "severity": "High",
        |      "severity_source": "Source",
        |      "vulnerable_component": "gav://com.testxml.test.core:component3:3.0",
        |      "component_physical_path": "catalogue-frontend-4.254.0/some/physical/path",
        |      "impacted_artifact": "fooBar",
        |      "impact_path": [
        |        "hello",
        |        "world"
        |      ],
        |      "path": "webstore-local/slugs/catalogue-frontend/catalogue-frontend_4.254.0_0.0.1.tgz",
        |      "fixed_versions": [
        |        "3.1"
        |      ],
        |      "published": {
        |        "$date":  { "$numberLong": "1678976870928" }
        |      },
        |      "artifact_scan_time": {
        |        "$date":  { "$numberLong": "1678976870928" }
        |      },
        |      "issue_id": "XRAY-000003",
        |      "package_type": "maven",
        |      "provider": "test",
        |      "description": "This is an exploit description",
        |      "references": [
        |        "foo.com",
        |        "bar.net"
        |      ],
        |      "project_keys": []
        |    }""".stripMargin

    lazy val vulnerabilityEntryV1xMissingFieldsMongo: String =
      """
        |   {
        |      "cves": [
        |        {
        |          "cve": "CVE-2022-12345",
        |          "cvss_v3_score": 8,
        |          "cvss_v3_vector": "test"
        |        }
        |      ],
        |      "cvss3_max_score": 8,
        |      "summary": "This is an exploit",
        |      "severity": "High",
        |      "severity_source": "Source",
        |      "vulnerable_component": "gav://com.testxml.test.core:component3:3.0",
        |      "component_physical_path": "catalogue-frontend-4.254.0/some/physical/path",
        |      "impacted_artifact": "fooBar",
        |      "impact_path": [
        |        "hello",
        |        "world"
        |      ],
        |      "path": "webstore-local/slugs/catalogue-frontend/catalogue-frontend_4.254.0_0.0.1.tgz",
        |      "fixed_versions": [
        |        "3.1"
        |      ],
        |      "published": {
        |        "$date":  { "$numberLong": "1678976870928" }
        |      },
        |      "artifact_scan_time": {
        |        "$date":  { "$numberLong": "1678976870928" }
        |      },
        |      "issue_id": "XRAY-000003",
        |      "package_type": "maven",
        |      "provider": "test",
        |      "project_keys": []
        |    }""".stripMargin

