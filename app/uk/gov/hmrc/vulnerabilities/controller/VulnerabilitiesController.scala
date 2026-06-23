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

package uk.gov.hmrc.vulnerabilities.controller

import play.api.Logging
import play.api.libs.json.{Json, Format, Writes}
import play.api.mvc.{Action, AnyContent, ControllerComponents, RequestHeader}
import uk.gov.hmrc.play.bootstrap.backend.controller.BackendController
import uk.gov.hmrc.vulnerabilities.model.*
import uk.gov.hmrc.vulnerabilities.persistence.{AssessmentsRepository, ReportRepository, VulnerabilityAgeRepository}
import uk.gov.hmrc.vulnerabilities.service.TeamService

import javax.inject.{Inject, Singleton}
import scala.concurrent.{Future, ExecutionContext}
import scala.util.{Failure, Success}

@Singleton()
class VulnerabilitiesController @Inject()(
  cc                        : ControllerComponents,
  assessmentsRepository     : AssessmentsRepository,
  reportRepository          : ReportRepository,
  teamService               : TeamService,
  vulnerabilityAgeRepository: VulnerabilityAgeRepository
)(using
  ExecutionContext
)
  extends BackendController(cc)
     with Logging:

  def getSummaries(
    flag           : Option[SlugInfoFlag]
  , service        : Option[ServiceName]
  , version        : Option[Version]
  , team           : Option[TeamName]
  , digitalService : Option[DigitalService]
  , curationStatus : Option[CurationStatus]
  ): Action[AnyContent] =
    Action.async: request =>
      // TODO flag is required if service + version are not provided
      given RequestHeader = request
      given Format[VulnerabilitySummary] = VulnerabilitySummary.apiFormat
      for
        serviceNames    <- (service, team, digitalService) match
                             case (None   , None, None) => Future.successful(None)
                             case (Some(s), _   , _   ) => Future.successful(Some(Seq(s)))
                             case (_      , _   , _   ) => teamService.services(team, digitalService).map(Some.apply)
        reports         <- reportRepository.find(flag, serviceNames, version)
        artefactToTeams <- teamService.artefactToTeams()
        firstDetected   <- vulnerabilityAgeRepository.firstDetected()
        assessments     <- assessmentsRepository.getAssessments().map(_.map(a => a.id -> a).toMap)
        allSummaries    =
                         for
                           report      <- reports
                           row         <- report.rows
                           cveId       =  row.cves.flatMap(_.cveId).headOption.getOrElse(row.issueId)
                           assessment  =  assessments.get(cveId)
                           if curationStatus.fold(true)(_ == assessment.fold(CurationStatus.Uncurated)(_.curationStatus))
                           compName    =  row.vulnerableComponent.split(":").dropRight(1).mkString(":")
                           compVersion =  row.vulnerableComponent.split(":").last
                           teams       =  artefactToTeams.getOrElse(ArtefactName(report.serviceName.asString), Seq.empty).sorted // report serviceName is really ArtefactName
                         yield
                           VulnerabilitySummary(
                            distinctVulnerability = DistinctVulnerability(
                                                      vulnerableComponentName    = compName,
                                                      vulnerableComponentVersion = compVersion,
                                                      vulnerableComponents       = Seq(VulnerableComponent(compName, compVersion)),
                                                      id                         = cveId,
                                                      score                      = row.cvss3MaxScore,
                                                      summary                    = row.summary,
                                                      description                = row.description,
                                                      fixedVersions              = Some(row.fixedVersions),
                                                      references                 = row.references,
                                                      publishedDate              = row.published,
                                                      firstDetected              = firstDetected.get(cveId),
                                                      assessment                 = assessment.map(_.assessment),
                                                      curationStatus             = assessment.fold(CurationStatus.Uncurated)(_.curationStatus),
                                                      ticket                     = assessment.map(_.ticket)
                                                    ),
                             occurrences          = Seq(VulnerabilityOccurrence(
                                                      service                    = report.serviceName.asString,
                                                      serviceVersion             = report.serviceVersion.original,
                                                      componentPathInSlug        = row.componentPhysicalPath,
                                                      importedBy                 = row.importedBy,
                                                      teams                      = teams,
                                                      envs                       = ( Option.when(report.development )(SlugInfoFlag.Development.asString ) ++
                                                                                     Option.when(report.integration )(SlugInfoFlag.Integration.asString ) ++
                                                                                     Option.when(report.qa          )(SlugInfoFlag.QA.asString          ) ++
                                                                                     Option.when(report.staging     )(SlugInfoFlag.Staging.asString     ) ++
                                                                                     Option.when(report.externalTest)(SlugInfoFlag.ExternalTest.asString) ++
                                                                                     Option.when(report.production  )(SlugInfoFlag.Production.asString  )
                                                                                   ).toSeq,
                                                      vulnerableComponentName    = compName,
                                                      vulnerableComponentVersion = compVersion
                                                    )),
                             teams                = teams,
                             generatedDate        = report.generatedDate
                           )
        summaries     = allSummaries
                          .sortBy(_.generatedDate)
                          .groupBy(_.distinctVulnerability.id)
                          .collect:
                            case (_, x +: xs) => x.copy(
                                                   distinctVulnerability = x.distinctVulnerability.copy(vulnerableComponents =
                                                                             (x.distinctVulnerability.vulnerableComponents ++ xs.flatMap(_.distinctVulnerability.vulnerableComponents))
                                                                               .distinct.sortBy(o => (o.component, o.version))
                                                                           )
                                                 , occurrences           = x.occurrences ++ xs.flatMap(_.occurrences)
                                                 , teams                 = (x.teams ++ xs.flatMap(_.teams)).distinct.sorted
                                                 )
                            case (_, List(x: VulnerabilitySummary))
                                              => x
      yield Ok(Json.toJson(summaries))

  def getReportCounts(
    flag          : SlugInfoFlag,
    service       : Option[ServiceName],
    team          : Option[TeamName],
    digitalService: Option[DigitalService]
  ): Action[AnyContent] =
    Action.async: request =>
      given RequestHeader = request
      given Writes[TotalVulnerabilityCount] = TotalVulnerabilityCount.writes
      val startedAt     = System.nanoTime()
      val diagnosticsId = java.lang.Long.toHexString(startedAt)
      logger.info(s"getReportCounts.start diagnosticsId=$diagnosticsId flag=${flag.asString} service=${service.map(_.asString)} team=${team.map(_.asString)} digitalService=${digitalService.map(_.asString)}")
      for
        serviceNames <- timedGetReportCounts(diagnosticsId, startedAt, "serviceNames")(
                          (service, team, digitalService) match
                            case (None   , None   , None) => Future.successful(None)
                            case (Some(s), _      , _   ) => Future.successful(Some(Seq(s)))
                            case (_      , _      , _   ) => teamService.services(team, digitalService).map(Some.apply)
                        )(serviceNames => s"serviceNames=${serviceNames.fold("none")(_.size.toString)}")
        reports      <- timedGetReportCounts(diagnosticsId, startedAt, "rawReports.find")(
                          reportRepository.find(Some(flag), serviceNames, version = None)
                        )(reports => s"reports=${reports.size} rows=${reports.map(_.rows.size).sum}")
        assessments  <- timedGetReportCounts(diagnosticsId, startedAt, "assessments.find")(
                          assessmentsRepository.getAssessments()
                        )(assessments => s"assessments=${assessments.size}")
        result       =
                        val countStartedAt = System.nanoTime()
                        val counts =
                          reports.map: report =>
                            val cves = report.rows.flatMap(_.cves.flatMap(_.cveId)).distinct
                            TotalVulnerabilityCount(
                              service              = report.serviceName
                            , actionRequired       = cves.filter   (cveId => assessments.exists(a => a.id == cveId && a.curationStatus == CurationStatus.ActionRequired      )).size
                            , noActionRequired     = cves.filter   (cveId => assessments.exists(a => a.id == cveId && a.curationStatus == CurationStatus.NoActionRequired    )).size
                            , investigationOngoing = cves.filter   (cveId => assessments.exists(a => a.id == cveId && a.curationStatus == CurationStatus.InvestigationOngoing)).size
                            , uncurated            = cves.filterNot(cveId => assessments.exists(a => a.id == cveId                                                           )).size
                            )
                        logger.info(s"getReportCounts.counts.done diagnosticsId=$diagnosticsId services=${counts.size} tookMillis=${elapsedMillis(countStartedAt)} totalTookMillis=${elapsedMillis(startedAt)}")
                        counts
        _            =  logger.info(s"getReportCounts.complete diagnosticsId=$diagnosticsId services=${result.size} totalTookMillis=${elapsedMillis(startedAt)}")
      yield Ok(Json.toJson(result))

  // temp endpoint till we work out how to display vulnerabilities on the service page
  def getDeployedReportCount(
    service: ServiceName
  ): Action[AnyContent] =
    Action.async: _ =>
      given tvw: Writes[TotalVulnerabilityCount] = TotalVulnerabilityCount.writes
      for
        reports     <- reportRepository.findDeployed(service)
        assessments <- assessmentsRepository.getAssessments()
        cves        =  reports.flatMap(_.rows.flatMap(_.cves.flatMap(_.cveId))).distinct
        result      =  TotalVulnerabilityCount(
                         service              = service
                       , actionRequired       = cves.filter   (cveId => assessments.exists(a => a.id == cveId && a.curationStatus == CurationStatus.ActionRequired      )).size
                       , noActionRequired     = cves.filter   (cveId => assessments.exists(a => a.id == cveId && a.curationStatus == CurationStatus.NoActionRequired    )).size
                       , investigationOngoing = cves.filter   (cveId => assessments.exists(a => a.id == cveId && a.curationStatus == CurationStatus.InvestigationOngoing)).size
                       , uncurated            = cves.filterNot(cveId => assessments.exists(a => a.id == cveId                                                           )).size
                       )
      yield
        if   reports.isEmpty
        then NotFound
        else Ok(Json.toJson(result))

  private def timedGetReportCounts[A](diagnosticsId: String, totalStartedAt: Long, label: String)(future: Future[A])(details: A => String): Future[A] =
    val stepStartedAt = System.nanoTime()
    future.andThen:
      case Success(value) => logger.info(s"getReportCounts.$label.done diagnosticsId=$diagnosticsId ${details(value)} tookMillis=${elapsedMillis(stepStartedAt)} totalTookMillis=${elapsedMillis(totalStartedAt)}")
      case Failure(ex)    => logger.warn(s"getReportCounts.$label.failed diagnosticsId=$diagnosticsId tookMillis=${elapsedMillis(stepStartedAt)} totalTookMillis=${elapsedMillis(totalStartedAt)}", ex)

  private def elapsedMillis(startedAt: Long): Long =
    (System.nanoTime() - startedAt) / 1000000
