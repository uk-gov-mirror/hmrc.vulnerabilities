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

package uk.gov.hmrc.vulnerabilities.connector

import org.apache.pekko.stream.{Materializer, SystemMaterializer}
import com.github.tomakehurst.wiremock.client.WireMock
import com.github.tomakehurst.wiremock.client.WireMock.{aResponse, containing, equalToJson, getRequestedFor, ok, postRequestedFor, stubFor, urlEqualTo, urlMatching}
import org.apache.pekko.actor.ActorSystem
import org.scalatest.OptionValues
import org.scalatest.concurrent.{IntegrationPatience, ScalaFutures}
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.scalatestplus.mockito.MockitoSugar
import play.api.Configuration
import play.api.libs.json.{Format, JsError, JsResult, JsSuccess, JsValue, Json}
import uk.gov.hmrc.crypto.Sensitive.SensitiveString
import uk.gov.hmrc.http.{HeaderCarrier, UpstreamErrorResponse}
import uk.gov.hmrc.http.test.{HttpClientV2Support, WireMockSupport}
import uk.gov.hmrc.vulnerabilities.model.Report.Vulnerability
import uk.gov.hmrc.vulnerabilities.model.{ArtifactoryToken, ImportedBy, Report, ServiceName, Version}

import java.time.temporal.ChronoUnit
import java.time.{Clock, Instant, LocalDate, ZoneOffset}
import scala.collection.immutable.Seq
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future

class XrayConnectorSpec
  extends AnyWordSpec
     with Matchers
     with OptionValues
     with ScalaFutures
     with IntegrationPatience
     with HttpClientV2Support
     with MockitoSugar
     with WireMockSupport:

  private given HeaderCarrier = HeaderCarrier()

  private val config = Configuration.from(Map(
    "xray.url"               -> s"${wireMockUrl}",
    "xray.token"             -> "testToken",
    "xray.username"          -> "user1",
    "xray.reports.retention" -> "1 day"
  ))

  private val actorSystem = ActorSystem("xray-connector-spec")
  private given Materializer = SystemMaterializer(actorSystem).materializer

  override def afterAll(): Unit =
    actorSystem.terminate()
    super.afterAll()

  private val startOfToday = LocalDate.now().atStartOfDay(ZoneOffset.UTC).toInstant
  private val connector    = XrayConnector(config, httpClientV2, clock = Clock.fixed(startOfToday, ZoneOffset.UTC))
  private val token        = ArtifactoryToken(
    accessToken  = SensitiveString("some-access-token")
  , refreshToken = SensitiveString("some-refresh-token")
  )

  "generateReport" when:
    "given a serviceVersionDeployments" should:
      "generate the expected request body" in:
        val expectedRequestBody =
          """{"name":"AppSec-report-service1_5_4_0","resources":{"repositories":[{"name":"webstore-local"}]},"filters":{"impacted_artifact":"*/service1_5.4.0_0.5.2.tgz"}}"""

        stubFor(WireMock.post(urlMatching("/xray/api/v1/reports/vulnerabilities"))
          .withRequestBody(containing(expectedRequestBody))
          .willReturn(
            aResponse().withBody(s"""{"report_id":1,"status":"pending"}""")
        ))

        connector.generateReport(ServiceName("service1"), Version("5.4.0"), "some/path/service1_5.4.0_0.5.2.tgz")(token).futureValue

        wireMockServer.verify(postRequestedFor(urlEqualTo("/xray/api/v1/reports/vulnerabilities"))
          .withRequestBody(equalToJson(expectedRequestBody)
        ))

    "it receives a valid response" should:
      "return a ReportRequestResponse" in:
        stubFor(WireMock.post(urlMatching("/xray/api/v1/reports/vulnerabilities"))
          .withRequestBody(containing("""{"name":"AppSec-report-service1_5_4_0","resources":{"repositories":[{"name":"webstore-local"}]},"filters":{"impacted_artifact":"*/service1_5.4.0_0.5.2.tgz"}}"""))
          .willReturn(aResponse().withBody(s"""{"report_id":1,"status":"pending"}""")))

        val res = connector.generateReport(ServiceName("service1"), Version("5.4.0"), "some/path/service1_5.4.0_0.5.2.tgz")(token).futureValue
        res shouldBe XrayConnector.ReportResponse(reportID = 1, status = "pending")

  "checkStatus" when:
    "given a reportId" should:
      "return a ReportStatus for the given reportID" in:
        stubFor(WireMock.get(urlMatching("/xray/api/v1/reports/1")).willReturn(
          aResponse().withBody(s"""{"id":1,"name":"AppSec-service1","report_type":"vulnerability",
               |"status":"completed","total_artifacts":2,"num_of_processed_artifacts":2,"progress":100,
               |"number_of_rows":1,"start_time":"2022-09-20T11:06:21Z","end_time":"2022-09-20T11:06:21Z",
               |"author":"joe.bloggs"}""".stripMargin)
        ))

        val res = connector.checkStatus(id = 1)(token).futureValue
        res shouldBe XrayConnector.ReportStatus(status = "completed", numberOfRows = 1, totalArtefacts = 2)

  "deleteReport" when:
    "xray returns a 4XX response" should:
      "return an UpstreamErrorResponse Exception" in:
        stubFor(WireMock.delete(urlMatching("/xray/api/v1/reports/1")).willReturn(
          aResponse().withStatus(404)
        ))

        val res = connector.deleteReportFromXray(reportId = 1)(token).failed.futureValue
        res shouldBe a [UpstreamErrorResponse]

    "xray returns a 5XX response" should:
      "return an UpstreamErrorResponse Exception" in:
        stubFor(WireMock.delete(urlMatching("/xray/api/v1/reports/1")).willReturn(
          aResponse().withStatus(500)
        ))

        val res = connector.deleteReportFromXray(reportId = 1)(token).failed.futureValue
        res shouldBe a [UpstreamErrorResponse]

  "getStaleReportDetails" should:
    "generated the expected request body" in:
      stubFor(WireMock.post(urlMatching("/xray/api/v1/reports\\?page_num=1&num_of_rows=100")).willReturn(
        aResponse()
          .withStatus(200)
          .withBody(
            s"""{"total_reports":2,"reports":[{"id":439753,"name":"AppSec-report-service1_1.0","report_type":"vulnerability","status":"completed","total_artifacts":2,"num_of_processed_artifacts":2,"progress":100,"number_of_rows":14,"start_time":"2023-01-01T11:20:20Z","end_time":"2023-08-07T11:20:21Z","author":"user1"},
               |{"id":439750,"name":"AppSec-report-service2>2.0","report_type":"vulnerability","status":"completed","total_artifacts":2,"num_of_processed_artifacts":2,"progress":100,"number_of_rows":14,"start_time":"2023-01-01T11:19:20Z","end_time":"2023-08-07T11:19:21Z","author":"user1"}]}""".stripMargin)
      ))

      connector.getStaleReportIds()(token).futureValue

      wireMockServer
        .verify(postRequestedFor(urlMatching("/xray/api/v1/reports\\?page_num=1&num_of_rows=100"))
          .withRequestBody(equalToJson(s"""{"filters":{"author":"user1","start_time_range":{"start":"2023-06-01T00:00:00Z","end":"${startOfToday.minus(1, ChronoUnit.DAYS)}"}}}""")))

    "return a Sequence of ReportIDs" in:
      stubFor(WireMock.post(urlMatching("/xray/api/v1/reports\\?page_num=1&num_of_rows=100")).willReturn(
        aResponse()
          .withStatus(200)
          .withBody(
            s"""{"total_reports":2,"reports":[{"id":439753,"name":"AppSec-report-service1_1.0","report_type":"vulnerability","status":"completed","total_artifacts":2,"num_of_processed_artifacts":2,"progress":100,"number_of_rows":14,"start_time":"2023-01-01T11:20:20Z","end_time":"2023-08-07T11:20:21Z","author":"user1"},
               |{"id":439750,"name":"AppSec-report-service2>2.0","report_type":"vulnerability","status":"completed","total_artifacts":2,"num_of_processed_artifacts":2,"progress":100,"number_of_rows":14,"start_time":"2023-01-01T11:19:20Z","end_time":"2023-08-07T11:19:21Z","author":"user1"}]}""".stripMargin)
      ))

      val res = connector.getStaleReportIds()(token).futureValue
      res shouldBe Seq(XrayConnector.ReportId(439753), XrayConnector.ReportId(439750))

    "return an UpstreamErrorResponse for 4XX errors" in:
      stubFor(WireMock.post(urlMatching("/xray/api/v1/reports\\?page_num=1&num_of_rows=100")).willReturn(
        aResponse().withStatus(429)
      ))

      val res = connector.getStaleReportIds()(token).failed.futureValue
      res shouldBe a [UpstreamErrorResponse]

    "return an UpstreamErrorResponse for 5XX errors" in:
      stubFor(WireMock.post(urlMatching("/xray/api/v1/reports\\?page_num=1&num_of_rows=100")).willReturn(
        aResponse().withStatus(500)
      ))

      val res = connector.getStaleReportIds()(token).failed.futureValue
      res shouldBe a [UpstreamErrorResponse]


  import uk.gov.hmrc.vulnerabilities.model.TestData.XRayModel._
  "Retrieving JFrog Vulnerability Report" when :
    val xRayReportJsonBaseVersion: String = s"""
         |{
         |  "total_reports": 2,
         |  "rows": [ $vuln1JsonV1, $vuln2JsonV1]
         |}""".stripMargin
    val xRayReportJsonV1MissingOptionalFields: String =
      s"""
         |{
         |  "total_reports": 2,
         |  "rows": [ $vuln1JsonV1xMissingFields, $vuln2JsonV1xMissingFields]
         |}""".stripMargin


    "downloadAndUnzipReport" when:

      "Retrieving a generated report zip file from X-Ray API for V1_x" should:
        val testServiceName    = ServiceName("platops-example-backend-microservice")
        val version            = Version("0.230.0")
        val expectedRawVersion = "0_230_0"
        val reportName         = s"AppSec-report-${testServiceName.asString}_$expectedRawVersion"

        val testReportId = 1234

        val zipBytes =
          Option(getClass.getResourceAsStream("/xray_report_v1_x-no_descriptions.zip"))
            .getOrElse(fail("Missing zip file from test resources: xray_report_v1_x-no_descriptions.zip"))
            .readAllBytes()

        "Download the report and unzip it and deserialize the JSON content into a List[Vulnerability]" in:
          val expectedUrl = s"/xray/api/v1/reports/export/$testReportId" +
                    s"?file_name=$reportName" +
                    s"&format=json"
          stubFor(WireMock.get(expectedUrl)
                          .willReturn(ok()
                            .withHeader("Content-Type", "application/zip")
                            .withBody(zipBytes)
                          )
                  )

          val vulnList = connector.downloadAndUnzipReport(testReportId, testServiceName, version)(token).futureValue
          wireMockServer.verify(1, getRequestedFor(urlEqualTo(expectedUrl)))

          vulnList match
            case Some((retrievedInstant, vulnerabilities)) =>
              retrievedInstant shouldBe startOfToday
              vulnerabilities should have size 11

              vulnerabilities.foreach { vuln =>
                vuln.issueId should startWith ("XRAY")
                vuln.cves should not be empty
                vuln.summary should not be empty
                vuln.summary.length should be >= 30

                vuln.description shouldBe empty
                vuln.references shouldBe empty
              }

              val testIssues = vulnerabilities.filter(_.issueId == "XRAY-522015")
              testIssues should have size 1
              testIssues.flatMap(_.cves) should contain (XrayConnector.CVE(cveId = Some("CVE-2023-35116"), cveV3Score = Some(4.7), cveV3Vector = Some("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H")))
              testIssues.head.severity shouldBe "Medium"
              testIssues.head.cvss3MaxScore should contain(4.7)

            case None => fail("Expected to retrieve a report containing List[Vulnerability] and created timestamp, but got None")

      "Retrieving an Xray V1 report" should:
        val xRayConnectorMockSource = xrayConnectorWithMockJsonReport(xRayReportJsonBaseVersion)
        "Deserialize the report JSON into a List[Vulnerability]" in:
          val result: Option[(Instant, Seq[XrayConnector.Vulnerability])] = xRayConnectorMockSource.downloadAndUnzipReport(1, ServiceName("service1"), Version("1.0.0"))(token).futureValue
          val retrievedVulnerabilityList = result.value._2.toList
          retrievedVulnerabilityList should have size 2

          val vuln1 = retrievedVulnerabilityList.find(_.issueId == "XRAY-000002").value

          vuln1.cves should contain (XrayConnector.CVE(cveId = Some("CVE-2021-99999"), cveV3Score = Some(7.0), cveV3Vector = Some("test1")))
          vuln1.summary shouldBe "This is a lower severity exploit"
          vuln1.description should contain ("This is the first exploit")
          vuln1.references should contain allOf("foo.com", "bar.net")

          val vuln2 = retrievedVulnerabilityList.find(_.issueId == "XRAY-000003").value
          vuln2.cves should contain (XrayConnector.CVE(cveId = Some("CVE-2022-12345"), cveV3Score = Some(8.0), cveV3Vector = Some("test2")))
          vuln2.summary shouldBe "This is a higher severity exploit"
          vuln2.description should contain ("This is the second exploit")
          vuln2.references should contain allOf("buzz.com", "fizz.net")
      "Retrieving an Xray V1_x report with missing fields" should:
        val xRayConnectorMockSource = xrayConnectorWithMockJsonReport(xRayReportJsonV1MissingOptionalFields)

        "Deserialize the report JSON into a List[Vulnerability] with missing fields set to None" in:

          val result: Option[(Instant, Seq[XrayConnector.Vulnerability])] = xRayConnectorMockSource.downloadAndUnzipReport(1, ServiceName("service1"), Version("1.0.0"))(token).futureValue
          val retrievedVulnerabilityList = result.value._2.toList
          retrievedVulnerabilityList should have size 2

          val vuln1 = retrievedVulnerabilityList.find(_.issueId == "XRAY-000002").value

          vuln1.cves should contain (XrayConnector.CVE(cveId = Some("CVE-2021-99999"), cveV3Score = Some(7.0), cveV3Vector = Some("test1")))
          vuln1.summary shouldBe "This is a lower severity exploit"
          vuln1.description should be (empty)
          vuln1.severitySource should be (empty)
          vuln1.references should be (empty)

          val vuln2 = retrievedVulnerabilityList.find(_.issueId == "XRAY-000003").value
          vuln2.cves should contain(XrayConnector.CVE(cveId = Some("CVE-2022-12345"), cveV3Score = Some(8.0), cveV3Vector = Some("test2")))
          vuln2.summary shouldBe "This is a higher severity exploit"
          vuln2.description should be(empty)
          vuln2.severitySource should be(empty)
          vuln2.references should be(empty)


  private def xrayConnectorWithMockJsonReport(xRayReportJson: String): XrayConnector =
    new XrayConnector(
      config,
      httpClientV2,
      Clock.fixed(startOfToday, ZoneOffset.UTC)
      ) with VulnerabilityReportSource:

      override protected def getRawReportAsString(
        reportId: Int,
        serviceName: ServiceName,
        version: Version
      )(using HeaderCarrier)(token: ArtifactoryToken): Future[Option[String]] =
        Future.successful(Some(xRayReportJson))

