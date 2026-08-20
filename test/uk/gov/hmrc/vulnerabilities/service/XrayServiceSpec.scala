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

package uk.gov.hmrc.vulnerabilities.service

import org.apache.pekko.actor.ActorSystem
import org.apache.pekko.stream.{Materializer, SystemMaterializer}
import org.scalatest.BeforeAndAfterAll
import org.scalatest.concurrent.ScalaFutures
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.scalatestplus.mockito.MockitoSugar
import org.mockito.Mockito.*
import org.mockito.ArgumentMatchers.*
import org.scalatest.time.{Millis, Seconds, Span}
import play.api.Configuration
import uk.gov.hmrc.http.HeaderCarrier
import uk.gov.hmrc.http.client.HttpClientV2
import uk.gov.hmrc.play.bootstrap.config.ServicesConfig
import uk.gov.hmrc.vulnerabilities.connector.*
import uk.gov.hmrc.vulnerabilities.model.*
import uk.gov.hmrc.vulnerabilities.persistence.*

import java.time.{Clock, Instant, ZoneOffset}
import scala.collection.mutable
import scala.concurrent.{ExecutionContext, Future}

class XrayServiceSpec
  extends AnyWordSpec
    with Matchers
    with ScalaFutures
    with MockitoSugar
    with BeforeAndAfterAll:

  given ExecutionContext = ExecutionContext.global
  given HeaderCarrier    = HeaderCarrier()

  implicit val defaultPatience: PatienceConfig =
    PatienceConfig(timeout = Span(5, Seconds), interval = Span(5, Millis))

  given ActorSystem = ActorSystem("xray-service-test")

  override def afterAll(): Unit =
    ActorSystem("xray-service-test").terminate()
    super.afterAll()

  // ---- In-memory fake ArtefactProcessorConnector ----
  private val fakeServicesConfig = mock[ServicesConfig]
  when(fakeServicesConfig.baseUrl("artefact-processor")).thenReturn("http://unused")


  "XrayService" when:

    import XrayServiceTestSupport._
    "rescanStaleReports is called" should:
      val testReportId = 42
      "process the stale reports and update persisted XRay report vulnerabilities" in:
        val now = Instant.parse("2026-05-27T10:00:00Z")
        val generatedDateFromXray = now.plusSeconds(120)
        val staleReport = storedReport(
          generatedDate = now.minusSeconds(3600),
          scanned       = false,
          latest        = true,
          production    = true
        )

        val config = baseConfig(xrayEnabled = true)

        val fakeReportRepo = FakeReportRepository(
            report = staleReport,
            initialTestVulnerabiltiies = Nil
          )

        val artefactProcessorConnector = new FakeArtefactProcessorConnector
        val fakeXrayConnector = new FakeXrayConnector(
          config       = config,
          rowsToReturn = xrayVulnerabilityRows,
          generatedAt  = generatedDateFromXray,
          expectedReportId = testReportId
        )

        val buildAndDeployConnector    = mock[BuildDeployApiConnector]
        val serviceConfigsConnector    = mock[ServiceConfigsConnector]
        val vulnerabilityAgeRepository = mock[VulnerabilityAgeRepository]
        val tokenRepository            = mock[ArtifactoryTokenRepository]

        when(serviceConfigsConnector.artefactToRepos()).thenReturn(Future.successful(Seq.empty))
        when(vulnerabilityAgeRepository.insertNonExisting(any[Report])).thenReturn(Future.unit)
        when(tokenRepository.get()).thenReturn(Future.successful(None))

        val service = new XrayService(
          configuration              = config,
          buildAndDeployConnector    = buildAndDeployConnector,
          artefactProcessorConnector = artefactProcessorConnector,
          xrayConnector              = fakeXrayConnector,
          serviceConfigsConnector    = serviceConfigsConnector,
          system                     = ActorSystem("xray-service-test"),
          reportRepository           = fakeReportRepo,
          vulnerabilityAgeRepository = vulnerabilityAgeRepository,
          artifactoryTokenRepository = tokenRepository
          )

        val preStore = fakeReportRepo.getTestStore.values
        // precondition checks
        preStore should have size 1
        // currently no vulnerability reports should exist
        preStore.head.rows shouldBe empty
        preStore.map(_.scanned) should contain only false

        // scan / generate report
        service.rescanStaleReports(reportsBefore = now.minusSeconds(1800)).futureValue

        // post report run tests
        val store = fakeReportRepo.getTestStore.values
        store.size shouldBe 1
        val updatedReport = store.last
        updatedReport.generatedDate shouldBe generatedDateFromXray
        updatedReport.scanned shouldBe true
        updatedReport.latest shouldBe true
        updatedReport.production shouldBe true
        // determine new vulnerability reports have successfully been added
        updatedReport.rows.map(_.issueId) should contain allOf ("XRAY-707194", "XRAY-900382", "XRAY-710140")
        updatedReport.rows.find(_.issueId == "XRAY-900382").map(_.fixedVersions) shouldBe Some(Seq("1.8.1"))
        updatedReport.rows.find(_.issueId == "XRAY-901520").map(_.fixedVersions) shouldBe Some(Seq.empty)
        updatedReport.rows.filter(_.summary.isEmpty) should have size 0
        updatedReport.rows.map(_.description) should contain only None
        updatedReport.rows.map(_.references) should contain only Nil


        fakeXrayConnector.generateReportRequests should contain only(
          (ServiceName("platops-example-backend-microservice"), Version("0.230.0"),
            "webstore-local/slugs/platops-example-backend-microservice/platops-example-backend-microservice_0.230.0_0.5.2.tgz")
        )
        fakeXrayConnector.downloadAndUnzipReportRequests should contain only (
          (testReportId, ServiceName("platops-example-backend-microservice"), Version("0.230.0"))
        )
        fakeXrayConnector.deletedReportIds should contain only testReportId


  private def baseConfig(xrayEnabled: Boolean): Configuration =
    Configuration.from(Map(
      "xray.enabled"                -> xrayEnabled,
      "xray.reports.waitTime"       -> "1 second",
      "xray.fallback.accessToken"   -> "fallback-access",
      "xray.fallback.refreshToken"  -> "fallback-refresh",
      "xray.warnOnly"               -> Seq.empty,
      "xray.url"                    -> "http://xray-unused",
      "xray.username"               -> "xray-user",
      "xray.reports.retention"      -> "1 day"
    ))

  private def storedReport(
    serviceVersion: Version = Version("0.230.0"),
    slugUri: String = "https://repo/webstore-local/slugs/platops-example-backend-microservice/platops-example-backend-microservice_0.230.0_0.5.2.tgz",
    generatedDate: Instant,
    scanned: Boolean,
    latest: Boolean = false,
    production: Boolean = false,
    qa: Boolean = false,
    staging: Boolean = false,
    development: Boolean = false,
    integration: Boolean = false,
    externalTest: Boolean = false
  ): Report =
    Report(
      serviceName = ServiceName("platops-example-backend-microservice"),
      serviceVersion = serviceVersion,
      slugUri = slugUri,
      rows = Seq.empty,
      generatedDate = generatedDate,
      scanned = scanned,
      latest = latest,
      production = production,
      qa = qa,
      staging = staging,
      development = development,
      externalTest = externalTest,
      integration = integration
      )

  private lazy val xrayVulnerabilityRows: Seq[XrayConnector.Vulnerability] =
    Seq(
      XrayConnector.Vulnerability(
        cves = Seq(XrayConnector.CVE(cveId = Some("CVE-2025-52999"), cveV3Score = None, cveV3Vector = None)),
        cvss3MaxScore = None,
        summary = "jackson-core has deeply nested input parsing risk leading to StackOverflowError.",
        severity = "High",
        severitySource = None,
        vulnerableComponent = "gav://com.fasterxml.jackson.core:jackson-core:2.14.3",
        componentPhysicalPath = "platops-example-backend-microservice-0.230.0/lib/com.fasterxml.jackson.core.jackson-core-2.14.3.jar",
        impactedArtefact = "generic://sha256:4e8a41cc125be3aa57dec94d45e338798d6d78c3e53fe5ae7e02f8b5d3841f30/platops-example-backend-microservice_0.230.0_0.5.2.tgz",
        impactPath = Seq(
          "generic://sha256:4e8a41cc125be3aa57dec94d45e338798d6d78c3e53fe5ae7e02f8b5d3841f30/platops-example-backend-microservice_0.230.0_0.5.2.tgz",
          "gav://com.fasterxml.jackson.core:jackson-core:2.14.3"
          ),
        path = "webstore-local/slugs/platops-example-backend-microservice/platops-example-backend-microservice_0.230.0_0.5.2.tgz",
        fixedVersions = Seq("2.15.0"),
        published = Instant.parse("2025-06-27T16:18:39Z"),
        artefactScanTime = Instant.parse("2024-11-07T15:57:37Z"),
        issueId = "XRAY-707194",
        packageType = "maven",
        provider = None,
        description = None,
        references = Seq.empty,
        projectKeys = Seq.empty
        ),
      XrayConnector.Vulnerability(
        cves = Seq(XrayConnector.CVE(cveId = Some("CVE-2025-12183"), cveV3Score = None, cveV3Vector = None)),
        cvss3MaxScore = None,
        summary = "Out-of-bounds operations in lz4-java 1.8.0 and earlier.",
        severity = "High",
        severitySource = None,
        vulnerableComponent = "gav://org.lz4:lz4-java:1.8.0",
        componentPhysicalPath = "platops-example-backend-microservice-0.230.0/lib/org.lz4.lz4-java-1.8.0.jar",
        impactedArtefact = "generic://sha256:4e8a41cc125be3aa57dec94d45e338798d6d78c3e53fe5ae7e02f8b5d3841f30/platops-example-backend-microservice_0.230.0_0.5.2.tgz",
        impactPath = Seq(
          "generic://sha256:4e8a41cc125be3aa57dec94d45e338798d6d78c3e53fe5ae7e02f8b5d3841f30/platops-example-backend-microservice_0.230.0_0.5.2.tgz",
          "gav://org.lz4:lz4-java:1.8.0"
          ),
        path = "webstore-local/slugs/platops-example-backend-microservice/platops-example-backend-microservice_0.230.0_0.5.2.tgz",
        fixedVersions = Seq("1.8.1"),
        published = Instant.parse("2025-12-03T16:20:21Z"),
        artefactScanTime = Instant.parse("2024-11-07T15:57:37Z"),
        issueId = "XRAY-900382",
        packageType = "maven",
        provider = None,
        description = None,
        references = Seq.empty,
        projectKeys = Seq.empty
        ),
      XrayConnector.Vulnerability(
        cves = Seq(XrayConnector.CVE(cveId = Some("CVE-2025-66566"), cveV3Score = None, cveV3Vector = None)),
        cvss3MaxScore = None,
        summary = "Insufficient clearing of output buffers in lz4-java decompressors.",
        severity = "High",
        severitySource = None,
        vulnerableComponent = "gav://org.lz4:lz4-java:1.8.0",
        componentPhysicalPath = "platops-example-backend-microservice-0.230.0/lib/org.lz4.lz4-java-1.8.0.jar",
        impactedArtefact = "generic://sha256:4e8a41cc125be3aa57dec94d45e338798d6d78c3e53fe5ae7e02f8b5d3841f30/platops-example-backend-microservice_0.230.0_0.5.2.tgz",
        impactPath = Seq(
          "generic://sha256:4e8a41cc125be3aa57dec94d45e338798d6d78c3e53fe5ae7e02f8b5d3841f30/platops-example-backend-microservice_0.230.0_0.5.2.tgz",
          "gav://org.lz4:lz4-java:1.8.0"
          ),
        path = "webstore-local/slugs/platops-example-backend-microservice/platops-example-backend-microservice_0.230.0_0.5.2.tgz",
        fixedVersions = Seq.empty,
        published = Instant.parse("2025-12-05T20:17:54Z"),
        artefactScanTime = Instant.parse("2024-11-07T15:57:37Z"),
        issueId = "XRAY-901520",
        packageType = "maven",
        provider = None,
        description = None,
        references = Seq.empty,
        projectKeys = Seq.empty
        ),
      XrayConnector.Vulnerability(
        cves = Seq(XrayConnector.CVE(cveId = Some("CVE-2025-48924"), cveV3Score = Some(6.5), cveV3Vector = Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"))),
        cvss3MaxScore = Some(6.5),
        summary = "Uncontrolled recursion in Apache Commons Lang before 3.18.0.",
        severity = "Medium",
        severitySource = None,
        vulnerableComponent = "gav://org.apache.commons:commons-lang3:3.14.0",
        componentPhysicalPath = "platops-example-backend-microservice-0.230.0/lib/org.apache.commons.commons-lang3-3.14.0.jar",
        impactedArtefact = "generic://sha256:4e8a41cc125be3aa57dec94d45e338798d6d78c3e53fe5ae7e02f8b5d3841f30/platops-example-backend-microservice_0.230.0_0.5.2.tgz",
        impactPath = Seq(
          "generic://sha256:4e8a41cc125be3aa57dec94d45e338798d6d78c3e53fe5ae7e02f8b5d3841f30/platops-example-backend-microservice_0.230.0_0.5.2.tgz",
          "gav://org.apache.commons:commons-lang3:3.14.0"
          ),
        path = "webstore-local/slugs/platops-example-backend-microservice/platops-example-backend-microservice_0.230.0_0.5.2.tgz",
        fixedVersions = Seq("3.18.0"),
        published = Instant.parse("2025-07-12T02:13:52Z"),
        artefactScanTime = Instant.parse("2024-11-07T15:57:37Z"),
        issueId = "XRAY-710140",
        packageType = "maven",
        provider = None,
        description = None,
        references = Seq.empty,
        projectKeys = Seq.empty
        )
      )

  private class FakeArtefactProcessorConnector
    extends ArtefactProcessorConnector(
      servicesConfig = fakeServicesConfig,
      httpClientV2 = mock
      ):

    private val metaByVersion = mutable.Map.empty[(RepoName, Version), Option[ArtefactProcessorConnector.MetaArtefact]]

    def seedMeta(repoName: RepoName, version: Version, value: Option[ArtefactProcessorConnector.MetaArtefact]): Unit =
      metaByVersion.update((repoName, version), value)

    override def getMetaArtefact(repoName: RepoName, version: Version)(using HeaderCarrier): Future[Option[ArtefactProcessorConnector.MetaArtefact]] =
      Future.successful(metaByVersion.getOrElse((repoName, version), None))



