package com.typesafe.security.authorization

import com.typesafe.security.authorization.Activities._

class Group(members: Set[String]) extends SecuredObject {
  def containsMember(subject: Subject): Boolean = {
    subject match {
      case ExampleSubject(name) =>
        members.contains(name)
      case _ =>
        false
    }
  }

  override def toString = s"Group($members)"
}

class Organization(admin: String) extends SecuredObject {
  def isAdministeredBy(subject: Subject): Boolean = {
    subject match {
      case ExampleSubject(name) =>
        admin.equals(name)
      case _ =>
        false
    }
  }

  override def toString = s"Organization($admin)"
}

/**
 * Imagine this is a controller.
 */
object ExampleAuthorization extends App with AuthorizationMethods {

  val users = Set("jeff", "steve", "mutt")

  val group = new Group(Set("jeff", "steve"))

  val org1 = new Organization(admin = "mutt")
  val org2 = new Organization(admin = "steve")

  for (currentUser <- users) {
    implicit val context = new ExampleSecurityContext(currentUser)

    Console.println("ORG1 ACTIVITIES:")
    Console.println(s"Is user $currentUser authorized to read $org1?  ${isAuthorized(CanRead, org1)}")
    Console.println(s"Is user $currentUser authorized to manage $org1?  ${isAuthorized(CanManage, org1)}")
    Console.println(s"Is user $currentUser authorized to delete $org1?  ${isAuthorized(CanDelete, org1)}")
    Console.println("ORG2 ACTIVITIES:")
    Console.println(s"Is user $currentUser authorized to read $org2?  ${isAuthorized(CanRead, org2)}")
    Console.println(s"Is user $currentUser authorized to manage $org2?  ${isAuthorized(CanManage, org2)}")
    Console.println(s"Is user $currentUser authorized to delete $org2?  ${isAuthorized(CanDelete, org2)}")
    Console.println("GROUP ACTIVITIES:")
    Console.println(s"Is user $currentUser authorized to read $group?  ${isAuthorized(CanRead, group)}")
    Console.println(s"Is user $currentUser authorized to manage $group?  ${isAuthorized(CanManage, group)}")
    Console.println(s"Is user $currentUser authorized to delete $group?  ${isAuthorized(CanDelete, group)}")
  }
}

/**
 * Subject is going to be a wrapper around User.
 */
case class ExampleSubject(name: String) extends Subject

object ExampleAbility {
  def apply(): ExampleAbility = new ExampleAbility()
}

class ExampleAbility extends Ability {

  import Activities._

  val rules = Set(
    new Rule(classOf[Organization], CanManage, { (subject, securedObject) =>
      securedObject match {
        case organization: Organization =>
          organization.isAdministeredBy(subject)
        case _ =>
          false
      }
    }),
    new Rule(classOf[Organization], CanDelete, { (subject, securedObject) =>
      securedObject match {
        case organization: Organization =>
          organization.isAdministeredBy(subject)
        case _ =>
          false
      }
    }),
    new Rule(classOf[Organization], CanRead, { (subject, securedObject) => true}),
    new Rule(classOf[Group], CanRead, { (subject, securedObject) =>
      securedObject match {
        case group: Group =>
          group.containsMember(subject)
        case _ =>
          false
      }
    })
  )
}

class ExampleSecurityContext(name: String) extends SecurityContext {

  override val subject: Subject = ExampleSubject(name)

  override val ability: Ability = ExampleAbility()
}
