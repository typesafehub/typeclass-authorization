package com.typesafe.security.authorization

class ExampleSecurityContext(name: String) extends SecurityContext {
  override val subject: Subject = new ExampleSubject(name)
}

case class ExampleSubject(name: String) extends Subject

/**
 * Imagine this is a controller.
 */
object ExampleAuthorization extends App {
  val users = Set("jeff", "steve", "mutt")

  val group = new Group(Set("jeff", "steve"))

  val org1 = new Organization(admin = "mutt")
  val org2 = new Organization(admin = "steve")

  for (currentUser <- users) {
    implicit val context = new ExampleSecurityContext(currentUser)

    val groupRead = CanRead(group)
    println(s"$group is readable by $currentUser: $groupRead")

    val org1Read = CanRead(org1)
    println(s"$org1 is readable by $currentUser: $org1Read")

    val org2Read = CanRead(org2)
    println(s"$org2 is readable by $currentUser: $org2Read")

    try {
      CanRead.lambda(group) {
        println("Can execute lambda!")
      }
    } catch {
      case e:UnauthorizedException =>
        println("whelp.")
    }
  }
}
