package com.typesafe.security.authorization

/**
 * Defines an example authorization application using type classes.
 */
object ExampleAuthorization extends App {

  /**
   * An organization contains exactly one admin, represented as a string.
   */
  class Organization(admin: String) extends SecuredObject {
    def isAdministeredBy(name: String): Boolean = admin.equals(name)
    override def toString = s"Organization($admin)"
  }

  /**
   * A group contains a set of example members, each represented as a string.
   */
  class Group(members: Set[String]) extends SecuredObject {
    def contains(name: String): Boolean = members.contains(name)
    override def toString = s"Group($members)"

    /**
     * Returns the execution of the block if the group is readable by the current context.
     */
    def readable[T](block: => T)(implicit ev: Readable[Group], context: SecurityContext): T = {
      ev.readableBlock(this)(block)(context)
    }
  }

  /**
   * The subject returns the security principal.
   */
  case class ExampleSubject(name: String) extends Subject

  /**
   * The example security context returns the Subject.
   */
  class ExampleSecurityContext(name: String) extends SecurityContext {
    override val subject: Subject = new ExampleSubject(name)
  }

  /**
   * This implicit evidence provides the "glue" to connect a Readable to a Group.
   */
  implicit object ExampleSubjectGroupReadable extends Readable[Group] {
    def isReadable(group: Group, context: SecurityContext): Boolean = {
      context.subject match {
        case ExampleSubject(name) =>
          group.contains(name)
        case _ =>
          false
      }
    }
  }

  /**
   * This implicit evidence provides the type class glue to connect a Readable with an Organization.
   */
  implicit object ExampleSubjectOrganizationReadable extends Readable[Organization] {
    def isReadable(org: Organization, context: SecurityContext): Boolean = {
      context.subject match {
        case ExampleSubject(name) =>
          org.isAdministeredBy(name)
        case _ =>
          false
      }
    }
  }

  val users = Set("jeff", "steve", "mutt")

  val steveAndJeffsGroup = new Group(Set("jeff", "steve"))

  val muttsOrg = new Organization(admin = "mutt")

  val stevesOrg = new Organization(admin = "steve")

  /**
   * For each user, ask whether they have read access to group and organization.
   */
  for (currentUser <- users) {
    implicit val context = new ExampleSecurityContext(currentUser)

    println(s"Is $steveAndJeffsGroup readable by $currentUser? ${Readable(steveAndJeffsGroup)}")
    println(s"Is $muttsOrg readable by $currentUser? ${Readable(muttsOrg)}")
    println(s"Is $stevesOrg readable by $currentUser? ${Readable(stevesOrg)}")

    try {
      val result: String = steveAndJeffsGroup.readable {
        s"$currentUser can execute readable for $steveAndJeffsGroup!"
      }
      println(result)
    } catch {
      case e:UnauthorizedException =>
        println(s"$currentUser cannot execute readable for $steveAndJeffsGroup!")
    }
  }
}
