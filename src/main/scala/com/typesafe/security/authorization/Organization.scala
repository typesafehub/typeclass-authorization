package com.typesafe.security.authorization

class Organization(admin: String) extends SecuredObject {

  def isAdministeredBy(name: String): Boolean = {
    admin.equals(name)
  }

  override def toString = s"Organization($admin)"
}

object Organization {

  implicit object OrganizationReadable extends Readable[Organization] {

    def isReadable(org: Organization, context: SecurityContext): Boolean = {
      context.subject match {
        case ExampleSubject(name) =>
          org.isAdministeredBy(name)
        case _ =>
          false
      }
    }

    def readableBlock[T](org: Organization)(block: => T)(implicit context: SecurityContext): T = {
      if (isReadable(org, context)) {
        block
      } else {
        throw new UnauthorizedException("Not authorized")
      }
    }
  }
}