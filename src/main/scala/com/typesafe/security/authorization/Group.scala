package com.typesafe.security.authorization

class Group(members: Set[String]) extends SecuredObject {

  def contains(name: String): Boolean = members.contains(name)

  override def toString = s"Group($members)"
}

object Group {

  implicit object GroupReadable extends Readable[Group] {

    def isReadable(group: Group, context: SecurityContext): Boolean = {
      context.subject match {
        case ExampleSubject(name) =>
          group.contains(name)
        case _ =>
          false
      }
    }

    def readableBlock[T](group: Group)(block: => T)(implicit context: SecurityContext): T = {
      if (isReadable(group, context)) {
        block
      } else {
        throw new UnauthorizedException("Not authorized")
      }
    }
  }
}
