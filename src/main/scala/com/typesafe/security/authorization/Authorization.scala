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
 * Thrown when an application is unauthorized.
 */
class UnauthorizedException(message: String) extends Exception(message)

