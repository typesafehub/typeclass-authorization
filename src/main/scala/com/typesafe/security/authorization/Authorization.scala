package com.typesafe.security.authorization

/**
 * The subject is the security principal.
 */
trait Subject

/**
 * The secured object is the object to check permissions against.
 */
trait SecuredObject

/**
 * The security context returns a subject.  This is often implicit.
 */
trait SecurityContext {
  def subject: Subject
}

/**
 * A security operation that can return true or false.
 */
trait SecurityOperation[SO <: SecuredObject] {
  def apply(securedObject: SO, context: SecurityContext): Boolean

  def apply[T](securedObject: SO)(block: => T)(implicit context: SecurityContext): T = {
    if (apply(securedObject, context)) {
      block
    } else {
      throw new UnauthorizedException("Not authorized")
    }
  }
}

/**
 * Thrown when an application is unauthorized.
 */
class UnauthorizedException(message: String) extends Exception(message)

