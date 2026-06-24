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

import org.mongodb.scala.model.{Filters, IndexModel, IndexOptions, Indexes}
import uk.gov.hmrc.mongo.MongoComponent
import uk.gov.hmrc.mongo.play.json.PlayMongoRepository
import uk.gov.hmrc.vulnerabilities.model.{Assessment, CurationStatus}

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class AssessmentsRepository @Inject()(
  mongoComponent: MongoComponent
)(using
  ExecutionContext
) extends PlayMongoRepository[Assessment](
  collectionName = "assessments",
  mongoComponent = mongoComponent,
  domainFormat   = Assessment.mongoFormat,
  indexes        = Seq(IndexModel(Indexes.ascending("id"), IndexOptions().unique(true)))
):
  // No ttl required for this collection - contains assessments created by ourselves which will evolve over time
  override lazy val requiresTtlIndex = false

  // Note assessments are inserted into Mongo directly
  def getAssessments(curationStatus: Option[CurationStatus] = None): Future[Seq[Assessment]] =
    collection
      .find(curationStatus.fold(Filters.empty)(cs => Filters.equal("curationStatus", cs.asString)))
      .toFuture()
