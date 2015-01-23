package com.typesafe.security.authorization

trait Subject

trait SecuredObject

trait SecurityContext {
  def subject: Subject
}

abstract class Readable[SO] {

  def isReadable(securedObject: SO, context: SecurityContext): Boolean

  //def readableBlock[T](securedObject: SO)(block: => T)(context: SecurityContext): T
}

object CanRead {

  def apply[SO](so: SO)(implicit ev: Readable[SO], context: SecurityContext): Boolean = ev.isReadable(so, context)

  //def lambda[SO, T](so: SO)(block: => T)(implicit ev: Readable[SO], context: SecurityContext): T = ev.readableBlock(so)(block)(context)
}

class UnauthorizedException(message: String) extends Exception(message)

