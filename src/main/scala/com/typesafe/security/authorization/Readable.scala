package com.typesafe.security.authorization

/**
 * A trait that defines a "readable" capability on an object.
 */
trait Readable[SO <: SecuredObject] {

  def isReadable(securedObject: SO, context: SecurityContext): Boolean

  def readableBlock[T](securedObject: SO)(block: => T)(implicit context: SecurityContext): T = {
    if (isReadable(securedObject, context)) {
      block
    } else {
      throw new UnauthorizedException("Not authorized")
    }
  }
}

/**
 * Provides convenience Readable methods on a secured object.
 */
object Readable {

  /**
   * Returns whether the secured object "so" is readable by the subject defined in "context".
   */
  def apply[SO <: SecuredObject](so: SO)(implicit ev: Readable[SO], context: SecurityContext): Boolean = {
    ev.isReadable(so, context)
  }

}
