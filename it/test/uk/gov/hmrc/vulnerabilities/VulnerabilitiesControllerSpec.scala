/*
 * Copyright 2023 HM Revenue & Customs
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

package uk.gov.hmrc.vulnerabilities

import com.github.tomakehurst.wiremock.client.WireMock
import org.scalatest.concurrent.{Eventually, IntegrationPatience, ScalaFutures}
import org.scalatest.matchers.should.Matchers
import org.scalatest.prop.TableDrivenPropertyChecks._
import org.scalatest.wordspec.AnyWordSpec
import org.scalatestplus.play.guice.GuiceOneServerPerSuite
import play.api.Application
import play.api.inject.guice.GuiceApplicationBuilder
import play.api.libs.json.Format
import play.api.libs.ws.WSClient
import uk.gov.hmrc.http.test.WireMockSupport
import uk.gov.hmrc.mongo.test.CleanMongoCollectionSupport
import uk.gov.hmrc.vulnerabilities.model.*
import uk.gov.hmrc.vulnerabilities.persistence.ReportRepository

class VulnerabilitiesControllerSpec
  extends AnyWordSpec
     with Matchers
     with ScalaFutures
     with Eventually
     with IntegrationPatience
     with GuiceOneServerPerSuite
     with WireMockSupport
     with CleanMongoCollectionSupport:

  override def fakeApplication(): Application =
    GuiceApplicationBuilder()
      .configure(Map(
        "microservice.services.teams-and-repositories.port" -> wireMockPort,
        "microservice.services.service-configs.port"        -> wireMockPort,
        "xray.url"                                          -> wireMockUrl,
        "mongodb.uri"                                       -> mongoUri
      ))
      .build()

  private val wsClient = app.injector.instanceOf[WSClient]

  private val reportCollection = app.injector.instanceOf[ReportRepository]

  /*
   * This test exercises the fact that it is possible for a scheduler run to fail part of the way through.
   * When it retries 3 hours later it should only attempt to download reports that don't already exist
   * in the raw reports repository within the specified data cut off time. This means we don't have to
   * re-download the whole data set in case of transient error.
   */
  "Summaries" should:
    "vulnerabilities/api/summaries should return all" when:

      val startOfYear = java.time.Instant.parse("2022-01-01T00:00:00.000Z")
      val v1Vulnerability = Report.Vulnerability(
        cves                  = Seq(Report.CVE(cveId = Some("CVE-2022-12345"), cveV3Score = Some(8.0), cveV3Vector = Some("test"))),
        cvss3MaxScore         = Some(8.0),
        summary               = "summary",
        severity              = "High",
        severitySource        = Some("Source"),
        vulnerableComponent   = "gav://com.testxml.test.core:test-bind:1.5.9",
        componentPhysicalPath = "service1-0.835.0/some/physical/path",
        impactedArtefact      = "fooBar",
        impactPath            = Seq("hello", "world"),
        path                  = "test/slugs/service1/service1_0.835.0_0.0.1.tgz",
        fixedVersions         = Seq("1.6.0"),
        published             = startOfYear,
        artefactScanTime      = startOfYear,
        issueId               = "XRAY-000005",
        packageType           = "maven",
        provider              = Some("test"),
        description           = Some("This is an exploit"),
        references            = Seq("foo.com", "bar.net"),
        projectKeys           = Seq(),
        importedBy            = Some(ImportedBy(group = "some-group", artefact = "some-artefact", Version("0.1.0")))
      )

      val v2Vulnerability = v1Vulnerability.copy(
        severitySource = None,
        provider = None,
        description = None,
        references = Nil
      )



      val distinctVulnerabilityV1AllInfo = DistinctVulnerability(
        vulnerableComponentName    = "gav://com.testxml.test.core:test-bind",
        vulnerableComponentVersion = "1.5.9",
        vulnerableComponents       = Seq(VulnerableComponent("gav://com.testxml.test.core:test-bind", "1.5.9")),
        id                         = "CVE-2022-12345",
        score                      = Some(8.0),
        summary                    = "summary",
        description                = Some("This is an exploit"),
        fixedVersions              = Some(Seq("1.6.0")),
        references                 = Seq("foo.com", "bar.net"),
        publishedDate              = startOfYear,
        firstDetected              = None,
        assessment                 = None,
        curationStatus             = CurationStatus.Uncurated,
        ticket                     = None
      )
      val distinctVulnerabilityV2 = distinctVulnerabilityV1AllInfo.copy(
        description = None,
        references = Nil
      )

      val modelVersionData = Table(("Test vresion", "Persisted Vulnerability model", "Expected DistinctVulnerability"),
        ("V1", v1Vulnerability, distinctVulnerabilityV1AllInfo),
        ("V2 - some previously required fields optional", v2Vulnerability, distinctVulnerabilityV2)
      )

      forAll(modelVersionData):
        (ver, vulnModel, expectedDistinctVulnerability) =>
          s"Using model API $ver" in:
            //stubbing
            WireMock.stubFor:
              WireMock
                .get(WireMock.urlPathMatching("/api/v2/repositories"))
                .willReturn(WireMock.aResponse().withStatus(200).withBody("""[{"name": "service1", "teamNames": ["Team1", "Team2"]}]"""))

            WireMock.stubFor:
              WireMock
                .get(WireMock.urlPathMatching("/service-configs/service-repo-names"))
                .willReturn(WireMock.aResponse().withStatus(200).withBody("""[]"""))

            //helpers
            given Format[VulnerabilitySummary] = VulnerabilitySummary.apiFormat

            reportCollection.put:
              Report(
                serviceName    = ServiceName("service1"),
                serviceVersion = Version("0.835.0"),
                slugUri        = "https://artifactory/webstore-local/service1_0.8.35.0.tgz",
                rows           = Seq(vulnModel),
                generatedDate  = startOfYear,
                latest         = false,
                production     = true,
                staging        = true,
                externalTest   = false,
                qa             = false,
                development    = false,
                integration    = false,
                scanned        = true
              )

            eventually:
              val response = wsClient
                .url(resource("vulnerabilities/api/summaries"))
                .get()
                .futureValue

              response.status shouldBe 200
              val result = response.json.as[Seq[VulnerabilitySummary]]

              result.length shouldBe 1
              result shouldBe Seq(
                VulnerabilitySummary(
                    distinctVulnerability      = expectedDistinctVulnerability,
                    occurrences                = Seq(VulnerabilityOccurrence(
                    service                    = "service1",
                    serviceVersion             = "0.835.0",
                    componentPathInSlug        = "service1-0.835.0/some/physical/path",
                    teams                      = Seq(TeamName("Team1"), TeamName("Team2")),
                    envs                       = Seq("staging", "production"),
                    vulnerableComponentName    = "gav://com.testxml.test.core:test-bind",
                    vulnerableComponentVersion = "1.5.9",
                    importedBy                 = Some(ImportedBy(group = "some-group", artefact = "some-artefact", Version("0.1.0")))
                  )),
                  teams         = List(TeamName("Team1"), TeamName("Team2")),
                  generatedDate = startOfYear
                )
              )

  def resource(path: String): String =
    s"http://localhost:$port/$path"
