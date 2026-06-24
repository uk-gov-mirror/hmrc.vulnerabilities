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

package uk.gov.hmrc.vulnerabilities.persistence

import org.mongodb.scala.{MongoCollection, ObservableFuture}
import org.scalatest.concurrent.IntegrationPatience
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import play.api.Configuration
import uk.gov.hmrc.mongo.play.json.CollectionFactory
import uk.gov.hmrc.mongo.test.DefaultPlayMongoRepositorySupport
import uk.gov.hmrc.vulnerabilities.model.{Assessment, CurationStatus, ImportedBy, Report, TimelineEvent, ServiceName, SlugInfoFlag, Version}

import java.time.Instant
import scala.collection.immutable.Seq
import scala.concurrent.ExecutionContext.Implicits.global


class ReportRepositorySpec
  extends AnyWordSpec
     with Matchers
     with DefaultPlayMongoRepositorySupport[Report]
     with IntegrationPatience:

  //Tests exercise aggregation pipeline, which don't make use of indices.
  override protected def checkIndexedQueries: Boolean = false

  private val configuration = Configuration(
    "regex.exclusion" -> "^(?!.*ehcache.*/rest-management-private-classpath/META-INF/maven/.*).*"
  )

  override val repository: MongoReportRepository = MongoReportRepository(mongoComponent, configuration)

  private val now = Instant.now.truncatedTo(java.time.temporal.ChronoUnit.MILLIS)

  "find" should:
    "by service name" in new Setup:
      repository.collection.insertOne(report1).toFuture().futureValue
      repository.find(flag = None, serviceNames = Some(Seq(report1.serviceName)), version = Some(report1.serviceVersion)).futureValue shouldBe Seq(report1)

    "by vulnerability ids and only return matching rows" in new Setup:
      repository.collection.insertOne(report2).toFuture().futureValue

      repository
        .findByVulnerabilityIds(flag = Some(SlugInfoFlag.Latest), serviceNames = None, version = None, vulnerabilityIds = Seq("CVE-2021-99999"))
        .futureValue shouldBe Seq(report2.copy(rows = Seq(report2.rows.head)))

  "getTimelineData" should:
    "parse issue id for vulnerabilities with AND without CVE ids" in new Setup:
      repository.collection.insertMany(Seq(report1, report2)).toFuture().futureValue
      assessmentsCollection.insertMany(assessments).toFuture().futureValue

      val res = repository.getTimelineData(Instant.now()).futureValue
      res.map(_.id) should contain theSameElementsAs Seq("CVE-2022-12345", "CVE-2022-12345", "CVE-2021-99999")

    "extract the serviceName from the path" in new Setup:
      repository.collection.insertMany(Seq(report1, report2)).toFuture().futureValue
      assessmentsCollection.insertMany(assessments).toFuture().futureValue

      val res = repository.getTimelineData(Instant.now()).futureValue
      res.map(_.service) should contain theSameElementsAs Seq("service1", "service2", "service2")

    "default curationStatus to uncurated if the Vulnerability does not exist in the collecitons assessment" in new Setup:
      val rep1 = report1.copy(rows = report1.rows.map(_.copy(cves = Seq(Report.CVE(cveId = Some("DOES_NOT_EXIST"), cveV3Score = Some(8.0), cveV3Vector = Some("test"))))))

      repository.collection.insertOne(rep1).toFuture().futureValue
      assessmentsCollection.insertMany(assessments).toFuture().futureValue

      val res = repository.getTimelineData(Instant.now()).futureValue
      res.head.curationStatus shouldBe CurationStatus.Uncurated

    "fully transform raw reports to vulnerability timeline data, in which the data is grouped by service AND issue AND weekBeginning" in new Setup:
      val rep1 = report1.copy(latest = false, production = false, externalTest = false, staging = false, qa = false)
      val rep2 = report2 //contains two cves, so will create two vulnerabilities

      repository.collection.insertMany(Seq(rep1, rep2)).toFuture().futureValue
      assessmentsCollection.insertMany(assessments).toFuture().futureValue

      val res = repository.getTimelineData(Instant.parse("2022-12-19T00:00:00.00Z")).futureValue

      res.length shouldBe 2
      res should contain theSameElementsAs Seq(
        TimelineEvent(id = "CVE-2021-99999", service = "service2", weekBeginning = Instant.parse("2022-12-19T00:00:00.00Z"), teams = Seq(), curationStatus = CurationStatus.ActionRequired),
        TimelineEvent(id = "CVE-2022-12345", service = "service2", weekBeginning = Instant.parse("2022-12-19T00:00:00.00Z"), teams = Seq(), curationStatus = CurationStatus.NoActionRequired)
      )

    "fully transform raw reports to vulnerability timeline data, in which the data is grouped by service AND issue AND weekBeginning AND filter entry with invalid regex" in new Setup:
      val rep1 = report1
      val rep2 = report2.copy(rows = report2.rows.map(_.copy(componentPhysicalPath = "service2-3.0.4/lib/net.sf.ehcache.ehcache-2.10.9.2.jar/rest-management-private-classpath/META-INF/maven/com.fasterxml.jackson.core/jackson-databind/pom.xml" )))

      repository.collection.insertMany(Seq(rep1, rep2)).toFuture().futureValue
      assessmentsCollection.insertMany(assessments).toFuture().futureValue

      val res = repository.getTimelineData(Instant.parse("2022-12-19T00:00:00.00Z")).futureValue

      res.length shouldBe 1
      res should contain theSameElementsAs Seq(
        TimelineEvent(id = "CVE-2022-12345", service = "service1", weekBeginning = Instant.parse("2022-12-19T00:00:00.00Z"), teams = Seq(), curationStatus = CurationStatus.NoActionRequired)
      )

  trait Setup:
   val assessmentsCollection: MongoCollection[Assessment] = CollectionFactory.collection(mongoComponent.database, "assessments", Assessment.mongoFormat)
   lazy val assessments = Seq(
     Assessment(id = "CVE-2022-12345", assessment = "N/A", curationStatus = CurationStatus.NoActionRequired    , lastReviewed = now, ticket = "BDOG-1"),
     Assessment(id = "CVE-2021-99999", assessment = "N/A", curationStatus = CurationStatus.ActionRequired      , lastReviewed = now, ticket = "BDOG-2"),
   )

   lazy val report1: Report =
      Report(
        serviceName    = ServiceName("service1"),
        serviceVersion = Version("1.0.4"),
        slugUri        = "http://artifactory/webstore/service1_1.0.4.tgz",
        rows           = Seq(
                           Report.Vulnerability(
                             cves                  = Seq(Report.CVE(cveId = Some("CVE-2022-12345"), cveV3Score = Some(8.0), cveV3Vector = Some("test"))),
                             cvss3MaxScore         = Some(8.0),
                             summary               = "This is an exploit",
                             severity              = "High",
                             severitySource        = Some("Source"),
                             vulnerableComponent   = "gav://com.testxml.test.core:test-bind:1.5.9",
                             componentPhysicalPath = "service1-1.0.4/some/physical/path",
                             impactedArtefact      = "fooBar",
                             impactPath            = Seq("hello", "world"),
                             path                  = "test/slugs/service1/service1_1.0.4_0.0.1.tgz",
                             fixedVersions         = Seq("1.6.0"),
                             published             = now,
                             artefactScanTime      = now,
                             issueId               = "XRAY-000003",
                             packageType           = "maven",
                             provider              = Some("test"),
                             description           = Some("This is an exploit"),
                             references            = Seq("foo.com", "bar.net"),
                             projectKeys           = Seq(),
                             importedBy            = Some(ImportedBy(group = "some-group", artefact = "some-artefact", Version("0.1.0")))
                         )),
        generatedDate  = now,
        scanned        = true,
        latest         = true,
        production     = true,
        externalTest   = true,
        staging        = true,
        qa             = true,
        development    = true,
        integration    = true
      )

   lazy val report2: Report =
      Report(
        serviceName    = ServiceName("service2"),
        serviceVersion = Version("3.0.4"),
        slugUri        = "http://artifactory/webstore/service2_3.0.4.tgz",
        rows           = Seq(
                           Report.Vulnerability(
                             cves                  = Seq(Report.CVE(cveId = Some("CVE-2021-99999"), cveV3Score = Some(7.0), cveV3Vector = Some("test2"))),
                             cvss3MaxScore         = Some(7.0),
                             summary               = "This is an exploit",
                             severity              = "High",
                             severitySource        = Some("Source"),
                             vulnerableComponent   = "gav://com.testxml.test.core:test-bind:1.6.8",
                             componentPhysicalPath = "service2-3.0.4/some/physical/path",
                             impactedArtefact      = "fooBar",
                             impactPath            = Seq("hello", "world"),
                             path                  = "test/slugs/service2/service2_3.0.4_0.0.1.tgz",
                             fixedVersions         = Seq("1.6.9"),
                             published             = now,
                             artefactScanTime      = now,
                             issueId               = "XRAY-000002",
                             packageType           = "maven",
                             provider              = Some("test"),
                             description           = Some("This is an exploit"),
                             references            = Seq("foo.com", "bar.net"),
                             projectKeys           = Seq(),
                             importedBy            = Some(ImportedBy(group = "some-group", artefact = "some-artefact", Version("0.2.0")))
                           ),
                           Report.Vulnerability(
                             cves                  = Seq(Report.CVE(cveId = Some("CVE-2022-12345"), cveV3Score = Some(8.0), cveV3Vector = Some("test"))),
                             cvss3MaxScore         = Some(8.0),
                             summary               = "This is an exploit",
                             severity              = "High",
                             severitySource        = Some("Source"),
                             vulnerableComponent   = "gav://com.testxml.test.core:test-bind:1.5.9",
                             componentPhysicalPath = "service2-3.0.4/some/physical/path",
                             impactedArtefact      = "fooBar",
                             impactPath            = Seq("hello", "world"),
                             path                  = "test/slugs/service2/service2_3.0.4_0.0.1.tgz",
                             fixedVersions         = Seq("1.6.0"),
                             published             = now,
                             artefactScanTime      = now,
                             issueId               = "XRAY-000003",
                             packageType           = "maven",
                             provider              = Some("test"),
                             description           = Some("This is an exploit"),
                             references            = Seq("foo.com", "bar.net"),
                             projectKeys           = Seq(),
                             importedBy            = Some(ImportedBy(group = "some-group", artefact = "some-artefact", Version("0.1.0")))
                           )
                         ),
        generatedDate  = now,
        scanned        = true,
        latest         = true,
        production     = true,
        externalTest   = true,
        staging        = true,
        qa             = true,
        development    = true,
        integration    = true
      )
