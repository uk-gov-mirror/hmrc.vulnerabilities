import play.core.PlayVersion
import play.sbt.PlayImport._
import sbt.Keys.libraryDependencies
import sbt._

object AppDependencies {

  private val bootstrapPlayVersion = "10.7.0"
  private val hmrcMongoPlayVersion = "2.13.0"

  val compile = Seq(
    caffeine,
    "uk.gov.hmrc"             %% "bootstrap-backend-play-30"  % bootstrapPlayVersion,
    "uk.gov.hmrc.mongo"       %% "hmrc-mongo-play-30"         % hmrcMongoPlayVersion,
    "uk.gov.hmrc"             %% "crypto-json-play-30"        % "8.4.0",
    "org.typelevel"           %% "cats-core"                  % "2.13.0",
    "software.amazon.awssdk"  %  "sqs"                        % "2.31.64"
  )

  val test = Seq(
    "uk.gov.hmrc"             %% "bootstrap-test-play-30"     % bootstrapPlayVersion  % Test,
    "uk.gov.hmrc.mongo"       %% "hmrc-mongo-test-play-30"    % hmrcMongoPlayVersion  % Test
  )
}
